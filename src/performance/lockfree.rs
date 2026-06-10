// Lock-free data structures for high-performance concurrent access
use crossbeam::queue::{ArrayQueue, SegQueue};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Lock-free queue for packet processing
pub struct LockFreeQueue<T> {
    queue: Arc<SegQueue<T>>,
    size: Arc<AtomicUsize>,
}

impl<T> Default for LockFreeQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LockFreeQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(SegQueue::new()),
            size: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn push(&self, item: T) {
        self.queue.push(item);
        self.size.fetch_add(1, Ordering::Relaxed);
    }

    pub fn pop(&self) -> Option<T> {
        let item = self.queue.pop();
        if item.is_some() {
            self.size.fetch_sub(1, Ordering::Relaxed);
        }
        item
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Clone for LockFreeQueue<T> {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            size: Arc::clone(&self.size),
        }
    }
}

/// Bounded lock-free queue with fixed capacity
pub struct BoundedQueue<T> {
    queue: ArrayQueue<T>,
    dropped: AtomicU64,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        self.queue.push(item).inspect_err(|_item| {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        })
    }

    pub fn pop(&self) -> Option<T> {
        self.queue.pop()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Lock-free flag for shared state
pub struct AtomicFlag {
    flag: AtomicBool,
}

impl AtomicFlag {
    pub fn new(initial: bool) -> Self {
        Self {
            flag: AtomicBool::new(initial),
        }
    }

    pub fn set(&self, value: bool) {
        self.flag.store(value, Ordering::Release);
    }

    pub fn get(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    pub fn swap(&self, value: bool) -> bool {
        self.flag.swap(value, Ordering::AcqRel)
    }

    pub fn compare_exchange(&self, current: bool, new: bool) -> Result<bool, bool> {
        self.flag
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfree_queue_operations() {
        let queue = LockFreeQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push(1);
        queue.push(2);
        queue.push(3);

        assert_eq!(queue.len(), 3);
        assert!(!queue.is_empty());

        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.len(), 1);

        assert_eq!(queue.pop(), Some(3));
        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_bounded_queue() {
        let queue = BoundedQueue::new(2);
        assert_eq!(queue.capacity(), 2);
        assert!(queue.is_empty());

        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());
        assert!(queue.is_full());

        // Should fail and increment dropped counter
        assert!(queue.push(3).is_err());
        assert_eq!(queue.dropped_count(), 1);

        assert_eq!(queue.pop(), Some(1));
        assert!(!queue.is_full());
        assert!(queue.push(4).is_ok());
    }

    #[test]
    fn test_atomic_flag() {
        let flag = AtomicFlag::new(false);
        assert!(!flag.get());

        flag.set(true);
        assert!(flag.get());

        let old = flag.swap(false);
        assert!(old);
        assert!(!flag.get());
    }

    #[test]
    fn test_atomic_flag_compare_exchange() {
        let flag = AtomicFlag::new(false);

        // Should succeed
        assert!(flag.compare_exchange(false, true).is_ok());
        assert!(flag.get());

        // Should fail
        assert!(flag.compare_exchange(false, true).is_err());
        assert!(flag.get());
    }

    #[tokio::test]
    async fn test_lockfree_queue_concurrent() {
        let queue = LockFreeQueue::new();
        let queue_clone = queue.clone();

        let producer = tokio::spawn(async move {
            for i in 0..100 {
                queue_clone.push(i);
            }
        });

        let consumer = tokio::spawn(async move {
            let mut count = 0;
            while count < 100 {
                if queue.pop().is_some() {
                    count += 1;
                }
                tokio::task::yield_now().await;
            }
            count
        });

        producer.await.unwrap();
        let consumed = consumer.await.unwrap();
        assert_eq!(consumed, 100);
    }
}
