pub use alloc::sync::Arc;
use core::fmt;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use core::time::Duration;

use std::cell::RefCell;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::RwLock as StdRwLock;
use std::sync::RwLockReadGuard as StdRwLockReadGuard;
use std::sync::RwLockWriteGuard as StdRwLockWriteGuard;

#[cfg(feature = "std")]
use parking_lot::Condvar as StdCondvar;
use parking_lot::Mutex as StdMutex;
use parking_lot::MutexGuard as StdMutexGuard;

pub use parking_lot::WaitTimeoutResult;

use crate::prelude::*;

use super::{LockHeldState, LockTestExt};

#[cfg(feature = "backtrace")]
use {crate::prelude::hash_map, backtrace::Backtrace, std::sync::Once};

#[cfg(not(feature = "backtrace"))]
struct Backtrace {}
#[cfg(not(feature = "backtrace"))]
impl Backtrace {
	fn new() -> Backtrace {
		Backtrace {}
	}
}

pub type LockResult<Guard> = Result<Guard, ()>;

#[cfg(feature = "std")]
pub struct Condvar {
	inner: StdCondvar,
}

#[cfg(feature = "std")]
impl Condvar {
	pub fn new() -> Condvar {
		Condvar { inner: StdCondvar::new() }
	}

	pub fn wait_while<'a, T, F: FnMut(&mut T) -> bool>(
		&'a self, guard: MutexGuard<'a, T>, condition: F,
	) -> LockResult<MutexGuard<'a, T>> {
		let mutex: &'a Mutex<T> = guard.mutex;
		let mut lock = guard.into_inner();
		self.inner.wait_while(&mut lock, condition);
		Ok(MutexGuard { mutex, lock: Some(lock) })
	}

	#[allow(unused)]
	pub fn wait_timeout_while<'a, T, F: FnMut(&mut T) -> bool>(
		&'a self, guard: MutexGuard<'a, T>, dur: Duration, condition: F,
	) -> LockResult<(MutexGuard<'a, T>, WaitTimeoutResult)> {
		let mutex = guard.mutex;
		let mut lock = guard.into_inner();
		let e = self.inner.wait_while_for(&mut lock, condition, dur);
		Ok((MutexGuard { mutex, lock: Some(lock) }, e))
	}

	pub fn notify_all(&self) {
		self.inner.notify_all();
	}

	#[allow(unused)]
	pub fn notify_one(&self) {
		self.inner.notify_one();
	}
}

thread_local! {
	/// We track the set of locks currently held by a reference to their `LockMetadata`
	static LOCKS_HELD: RefCell<HashMap<u64, Arc<LockMetadata>>> = RefCell::new(new_hash_map());
}
static LOCK_IDX: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "backtrace")]
static mut LOCKS: Option<StdMutex<HashMap<String, Arc<LockMetadata>>>> = None;
#[cfg(feature = "backtrace")]
static LOCKS_INIT: Once = Once::new();

/// Metadata about a single lock, by id, the set of things locked-before it, and the backtrace of
/// when the Mutex itself was constructed.
struct LockMetadata {
	lock_idx: u64,
	locked_before: StdMutex<HashMap<u64, LockDep>>,
	_lock_construction_bt: Backtrace,
}

struct LockDep {
	lock: Arc<LockMetadata>,
	/// lockdep_trace is unused unless we're building with `backtrace`, so we mark it _
	_lockdep_trace: Backtrace,
}

// Locates the frame preceding the earliest `debug_sync` frame in the call stack. This ensures we
// can properly detect a lock's construction and acquiral callsites, since the latter may contain
// multiple `debug_sync` frames.
#[cfg(feature = "backtrace")]
fn locate_call_symbol(backtrace: &Backtrace) -> (String, Option<u32>) {
	// Find the earliest `debug_sync` frame (or that is in our tests) and use the frame preceding it
	// as the callsite. Note that the first few frames may be in the `backtrace` crate, so we have
	// to ignore those.
	let sync_mutex_constr_regex = regex::Regex::new(r"lightning.*debug_sync").unwrap();
	let mut found_debug_sync = false;
	let mut symbol_after_latest_debug_sync = None;
	for frame in backtrace.frames().iter() {
		for symbol in frame.symbols().iter() {
			if let Some(symbol_name) = symbol.name().map(|name| name.as_str()).flatten() {
				if !sync_mutex_constr_regex.is_match(symbol_name) {
					if found_debug_sync {
						symbol_after_latest_debug_sync = Some(symbol);
						found_debug_sync = false;
					}
				} else {
					found_debug_sync = true;
				}
			}
		}
	}
	let symbol = symbol_after_latest_debug_sync.unwrap_or_else(|| {
		panic!("Couldn't find lock call symbol in trace {:?}", backtrace);
	});
	(
		format!("{}:{}", symbol.filename().unwrap().display(), symbol.lineno().unwrap()),
		symbol.colno(),
	)
}

impl LockMetadata {
	fn new() -> Arc<LockMetadata> {
		let backtrace = Backtrace::new();
		let lock_idx = LOCK_IDX.fetch_add(1, Ordering::Relaxed) as u64;

		let res = Arc::new(LockMetadata {
			locked_before: StdMutex::new(new_hash_map()),
			lock_idx,
			_lock_construction_bt: backtrace,
		});

		#[cfg(feature = "backtrace")]
		{
			let (lock_constr_location, lock_constr_colno) =
				locate_call_symbol(&res._lock_construction_bt);
			LOCKS_INIT.call_once(|| unsafe {
				LOCKS = Some(StdMutex::new(new_hash_map()));
			});
			let mut locks = unsafe { LOCKS.as_ref() }.unwrap().lock();
			match locks.entry(lock_constr_location) {
				hash_map::Entry::Occupied(e) => {
					assert_eq!(lock_constr_colno,
						locate_call_symbol(&e.get()._lock_construction_bt).1,
						"Because Windows doesn't support column number results in backtraces, we cannot construct two mutexes on the same line or we risk lockorder detection false positives.");
					return Arc::clone(e.get());
				},
				hash_map::Entry::Vacant(e) => {
					e.insert(Arc::clone(&res));
				},
			}
		}
		res
	}

	fn pre_lock(this: &Arc<LockMetadata>, _double_lock_self_allowed: bool) {
		LOCKS_HELD.with(|held| {
			// For each lock that is currently held, check that no lock's `locked_before` set
			// includes the lock we're about to hold, which would imply a lockorder inversion.
			for (locked_idx, _locked) in held.borrow().iter() {
				if *locked_idx == this.lock_idx {
					// Note that with `feature = "backtrace"` set, we may be looking at different
					// instances of the same lock. Still, doing so is quite risky, a total order
					// must be maintained, and doing so across a set of otherwise-identical mutexes
					// is fraught with issues.
					#[cfg(feature = "backtrace")]
					debug_assert!(_double_lock_self_allowed,
						"Tried to acquire a lock while it was held!\nLock constructed at {}",
						locate_call_symbol(&this._lock_construction_bt).0);
					#[cfg(not(feature = "backtrace"))]
					panic!("Tried to acquire a lock while it was held!");
				}
			}
			for (_locked_idx, locked) in held.borrow().iter() {
				for (locked_dep_idx, _locked_dep) in locked.locked_before.lock().iter() {
					let is_dep_this_lock = *locked_dep_idx == this.lock_idx;
					let has_same_construction = *locked_dep_idx == locked.lock_idx;
					if is_dep_this_lock && !has_same_construction {
						#[allow(unused_mut, unused_assignments)]
						let mut has_same_callsite = false;
						#[cfg(feature = "backtrace")] {
							has_same_callsite = _double_lock_self_allowed &&
								locate_call_symbol(&_locked_dep._lockdep_trace) ==
									locate_call_symbol(&Backtrace::new());
						}
						if !has_same_callsite {
							#[cfg(feature = "backtrace")]
							panic!("Tried to violate existing lockorder.\nMutex that should be locked after the current lock was created at the following backtrace.\nNote that to get a backtrace for the lockorder violation, you should set RUST_BACKTRACE=1\nLock being taken constructed at: {} ({}):\n{:?}\nLock constructed at: {} ({})\n{:?}\n\nLock dep created at:\n{:?}\n\n",
								locate_call_symbol(&this._lock_construction_bt).0,
								this.lock_idx, this._lock_construction_bt,
								locate_call_symbol(&locked._lock_construction_bt).0,
								locked.lock_idx, locked._lock_construction_bt,
								_locked_dep._lockdep_trace);
							#[cfg(not(feature = "backtrace"))]
							panic!("Tried to violate existing lockorder. Build with the backtrace feature for more info.");
						}
					}
				}
				// Insert any already-held locks in our locked-before set.
				let mut locked_before = this.locked_before.lock();
				if !locked_before.contains_key(&locked.lock_idx) {
					let lockdep = LockDep { lock: Arc::clone(locked), _lockdep_trace: Backtrace::new() };
					locked_before.insert(lockdep.lock.lock_idx, lockdep);
				}
			}
			held.borrow_mut().insert(this.lock_idx, Arc::clone(this));
		});
	}

	fn held_by_thread(this: &Arc<LockMetadata>) -> LockHeldState {
		let mut res = LockHeldState::NotHeldByThread;
		LOCKS_HELD.with(|held| {
			for (locked_idx, _locked) in held.borrow().iter() {
				if *locked_idx == this.lock_idx {
					res = LockHeldState::HeldByThread;
				}
			}
		});
		res
	}

	fn try_locked(this: &Arc<LockMetadata>) {
		LOCKS_HELD.with(|held| {
			// Since a try-lock will simply fail if the lock is held already, we do not
			// consider try-locks to ever generate lockorder inversions. However, if a try-lock
			// succeeds, we do consider it to have created lockorder dependencies.
			let mut locked_before = this.locked_before.lock();
			for (locked_idx, locked) in held.borrow().iter() {
				if !locked_before.contains_key(locked_idx) {
					let lockdep =
						LockDep { lock: Arc::clone(locked), _lockdep_trace: Backtrace::new() };
					locked_before.insert(*locked_idx, lockdep);
				}
			}
			held.borrow_mut().insert(this.lock_idx, Arc::clone(this));
		});
	}
}

pub struct Mutex<T: Sized> {
	inner: StdMutex<T>,
	poisoned: AtomicBool,
	deps: Arc<LockMetadata>,
}

impl<T: Sized> Mutex<T> {
	pub(crate) fn into_inner(self) -> LockResult<T> {
		if self.poisoned.load(Ordering::Acquire) {
			Err(())
		} else {
			Ok(self.inner.into_inner())
		}
	}
}

impl<T: Sized + fmt::Debug> fmt::Debug for Mutex<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut d = f.debug_struct("Mutex");
		match self.try_lock() {
			Ok(guard) => {
				d.field("data", &&*guard);
			},
			Err(()) => {
				d.field("data", &format_args!("<locked>"));
			},
		}
		d.finish_non_exhaustive()
	}
}

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: Sized + 'a> {
	mutex: &'a Mutex<T>,
	lock: Option<StdMutexGuard<'a, T>>,
}

impl<'a, T: Sized> MutexGuard<'a, T> {
	#[cfg(feature = "std")]
	fn into_inner(self) -> StdMutexGuard<'a, T> {
		// Somewhat unclear why we cannot move out of self.lock, but doing so gets E0509.
		unsafe {
			let v: StdMutexGuard<'a, T> = std::ptr::read(self.lock.as_ref().unwrap());
			std::mem::forget(self);
			v
		}
	}
}

impl<T: Sized> Drop for MutexGuard<'_, T> {
	fn drop(&mut self) {
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.mutex.deps.lock_idx);
		});
		if std::thread::panicking() {
			self.mutex.poisoned.store(true, Ordering::Release);
		}
		StdMutexGuard::unlock_fair(self.lock.take().unwrap());
	}
}

impl<T: Sized> Deref for MutexGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.lock.as_ref().unwrap().deref()
	}
}

impl<T: Sized> DerefMut for MutexGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.lock.as_mut().unwrap().deref_mut()
	}
}

impl<T> Mutex<T> {
	pub fn new(inner: T) -> Mutex<T> {
		Mutex {
			inner: StdMutex::new(inner),
			poisoned: AtomicBool::new(false),
			deps: LockMetadata::new(),
		}
	}

	#[cfg(test)]
	/// Takes a lock without any deadlock detection logic. This should never exist in production
	/// code (the deadlock detection logic is important!) but can be used in tests where we're
	/// willing to risk deadlocks (accepting that simply no existing tests hit them).
	pub fn deadlocking_lock<'a>(&'a self) -> MutexGuard<'a, T> {
		let lock = self.inner.lock();
		if self.poisoned.load(Ordering::Acquire) {
			panic!();
		} else {
			MutexGuard { mutex: self, lock: Some(lock) }
		}
	}

	pub fn lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		LockMetadata::pre_lock(&self.deps, false);
		let lock = self.inner.lock();
		if self.poisoned.load(Ordering::Acquire) {
			Err(())
		} else {
			Ok(MutexGuard { mutex: self, lock: Some(lock) })
		}
	}

	pub fn try_lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		let res = self.inner.try_lock().ok_or(());
		if res.is_ok() {
			if self.poisoned.load(Ordering::Acquire) {
				return Err(());
			}
			LockMetadata::try_locked(&self.deps);
		}
		res.map(|lock| MutexGuard { mutex: self, lock: Some(lock) })
	}

	pub fn get_mut<'a>(&'a mut self) -> LockResult<&'a mut T> {
		if self.poisoned.load(Ordering::Acquire) {
			Err(())
		} else {
			Ok(self.inner.get_mut())
		}
	}
}

impl<'a, T: 'a> LockTestExt<'a> for Mutex<T> {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		LockMetadata::held_by_thread(&self.deps)
	}
	type ExclLock = MutexGuard<'a, T>;
	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> MutexGuard<'a, T> {
		LockMetadata::pre_lock(&self.deps, true);
		let lock = self.inner.lock();
		MutexGuard { mutex: self, lock: Some(lock) }
	}
}

pub struct RwLock<T: Sized> {
	inner: StdRwLock<T>,
	deps: Arc<LockMetadata>,
}

pub struct RwLockReadGuard<'a, T: Sized + 'a> {
	lock: &'a RwLock<T>,
	guard: StdRwLockReadGuard<'a, T>,
}

pub struct RwLockWriteGuard<'a, T: Sized + 'a> {
	lock: &'a RwLock<T>,
	guard: StdRwLockWriteGuard<'a, T>,
}

impl<T: Sized> Deref for RwLockReadGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.guard.deref()
	}
}

impl<T: Sized> Drop for RwLockReadGuard<'_, T> {
	fn drop(&mut self) {
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.lock.deps.lock_idx);
		});
	}
}

impl<T: Sized> Deref for RwLockWriteGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.guard.deref()
	}
}

impl<T: Sized> Drop for RwLockWriteGuard<'_, T> {
	fn drop(&mut self) {
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.lock.deps.lock_idx);
		});
	}
}

impl<T: Sized> DerefMut for RwLockWriteGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.guard.deref_mut()
	}
}

impl<T> RwLock<T> {
	pub fn new(inner: T) -> RwLock<T> {
		RwLock { inner: StdRwLock::new(inner), deps: LockMetadata::new() }
	}

	pub fn read<'a>(&'a self) -> LockResult<RwLockReadGuard<'a, T>> {
		// Note that while we could be taking a recursive read lock here, Rust's `RwLock` may
		// deadlock trying to take a second read lock if another thread is waiting on the write
		// lock. This behavior is platform dependent, but our in-tree `FairRwLock` guarantees
		// such a deadlock.
		LockMetadata::pre_lock(&self.deps, false);
		self.inner.read().map(|guard| RwLockReadGuard { lock: self, guard }).map_err(|_| ())
	}

	#[cfg(test)]
	/// Takes a read lock without any deadlock detection logic. This should never exist in
	/// production code (the deadlock detection logic is important!) but can be used in tests where
	/// we're willing to risk deadlocks (accepting that simply no existing tests hit them).
	pub fn deadlocking_read<'a>(&'a self) -> RwLockReadGuard<'a, T> {
		self.inner.read().map(|guard| RwLockReadGuard { lock: self, guard }).unwrap()
	}

	pub fn write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		LockMetadata::pre_lock(&self.deps, false);
		self.inner.write().map(|guard| RwLockWriteGuard { lock: self, guard }).map_err(|_| ())
	}

	pub fn try_write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		let res = self
			.inner
			.try_write()
			.map(|guard| RwLockWriteGuard { lock: self, guard })
			.map_err(|_| ());
		if res.is_ok() {
			LockMetadata::try_locked(&self.deps);
		}
		res
	}
}

impl<'a, T: 'a> LockTestExt<'a> for RwLock<T> {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		LockMetadata::held_by_thread(&self.deps)
	}
	type ExclLock = RwLockWriteGuard<'a, T>;
	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> RwLockWriteGuard<'a, T> {
		LockMetadata::pre_lock(&self.deps, true);
		self.inner.write().map(|guard| RwLockWriteGuard { lock: self, guard }).unwrap()
	}
}

pub type FairRwLock<T> = RwLock<T>;
