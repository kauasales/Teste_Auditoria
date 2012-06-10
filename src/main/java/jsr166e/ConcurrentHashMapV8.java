/*
 * Written by Doug Lea with assistance from members of JCP JSR-166
 * Expert Group and released to the public domain, as explained at
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

// Snapshot Tue Jun  5 14:56:09 2012  Doug Lea  (dl at altair)

package jsr166e;
import jsr166e.LongAdder;
import jsr166y.ThreadLocalRandom;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.Collection;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.AbstractCollection;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Enumeration;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;
import java.io.Serializable;

/**
 * A hash table supporting full concurrency of retrievals and
 * high expected concurrency for updates. This class obeys the
 * same functional specification as {@link java.util.Hashtable}, and
 * includes versions of methods corresponding to each method of
 * {@code Hashtable}. However, even though all operations are
 * thread-safe, retrieval operations do <em>not</em> entail locking,
 * and there is <em>not</em> any support for locking the entire table
 * in a way that prevents all access.  This class is fully
 * interoperable with {@code Hashtable} in programs that rely on its
 * thread safety but not on its synchronization details.
 *
 * <p> Retrieval operations (including {@code get}) generally do not
 * block, so may overlap with update operations (including {@code put}
 * and {@code remove}). Retrievals reflect the results of the most
 * recently <em>completed</em> update operations holding upon their
 * onset.  For aggregate operations such as {@code putAll} and {@code
 * clear}, concurrent retrievals may reflect insertion or removal of
 * only some entries.  Similarly, Iterators and Enumerations return
 * elements reflecting the state of the hash table at some point at or
 * since the creation of the iterator/enumeration.  They do
 * <em>not</em> throw {@link ConcurrentModificationException}.
 * However, iterators are designed to be used by only one thread at a
 * time.  Bear in mind that the results of aggregate status methods
 * including {@code size}, {@code isEmpty}, and {@code containsValue}
 * are typically useful only when a map is not undergoing concurrent
 * updates in other threads.  Otherwise the results of these methods
 * reflect transient states that may be adequate for monitoring
 * or estimation purposes, but not for program control.
 *
 * <p> The table is dynamically expanded when there are too many
 * collisions (i.e., keys that have distinct hash codes but fall into
 * the same slot modulo the table size), with the expected average
 * effect of maintaining roughly two bins per mapping (corresponding
 * to a 0.75 load factor threshold for resizing). There may be much
 * variance around this average as mappings are added and removed, but
 * overall, this maintains a commonly accepted time/space tradeoff for
 * hash tables.  However, resizing this or any other kind of hash
 * table may be a relatively slow operation. When possible, it is a
 * good idea to provide a size estimate as an optional {@code
 * initialCapacity} constructor argument. An additional optional
 * {@code loadFactor} constructor argument provides a further means of
 * customizing initial table capacity by specifying the table density
 * to be used in calculating the amount of space to allocate for the
 * given number of elements.  Also, for compatibility with previous
 * versions of this class, constructors may optionally specify an
 * expected {@code concurrencyLevel} as an additional hint for
 * internal sizing.  Note that using many keys with exactly the same
 * {@code hashCode()} is a sure way to slow down performance of any
 * hash table.
 *
 * <p>This class and its views and iterators implement all of the
 * <em>optional</em> methods of the {@link Map} and {@link Iterator}
 * interfaces.
 *
 * <p> Like {@link Hashtable} but unlike {@link HashMap}, this class
 * does <em>not</em> allow {@code null} to be used as a key or value.
 *
 * <p>This class is a member of the
 * <a href="{@docRoot}/../technotes/guides/collections/index.html">
 * Java Collections Framework</a>.
 *
 * <p><em>jsr166e note: This class is a candidate replacement for
 * java.util.concurrent.ConcurrentHashMap.<em>
 *
 * @since 1.5
 * @author Doug Lea
 * @param <K> the type of keys maintained by this map
 * @param <V> the type of mapped values
 */
public class ConcurrentHashMapV8<K, V>
        implements ConcurrentMap<K, V>, Serializable {
    private static final long serialVersionUID = 7249069246763182397L;

    /**
     * A function computing a mapping from the given key to a value.
     * This is a place-holder for an upcoming JDK8 interface.
     */
    public static interface MappingFunction<K, V> {
        /**
         * Returns a non-null value for the given key.
         *
         * @param key the (non-null) key
         * @return a non-null value
         */
        V map(K key);
    }

    /**
     * A function computing a new mapping given a key and its current
     * mapped value (or {@code null} if there is no current
     * mapping). This is a place-holder for an upcoming JDK8
     * interface.
     */
    public static interface RemappingFunction<K, V> {
        /**
         * Returns a new value given a key and its current value.
         *
         * @param key the (non-null) key
         * @param value the current value, or null if there is no mapping
         * @return a non-null value
         */
        V remap(K key, V value);
    }

    /*
     * Overview:
     *
     * The primary design goal of this hash table is to maintain
     * concurrent readability (typically method get(), but also
     * iterators and related methods) while minimizing update
     * contention. Secondary goals are to keep space consumption about
     * the same or better than java.util.HashMap, and to support high
     * initial insertion rates on an empty table by many threads.
     *
     * Each key-value mapping is held in a Node.  Because Node fields
     * can contain special values, they are defined using plain Object
     * types. Similarly in turn, all internal methods that use them
     * work off Object types. And similarly, so do the internal
     * methods of auxiliary iterator and view classes.  All public
     * generic typed methods relay in/out of these internal methods,
     * supplying null-checks and casts as needed. This also allows
     * many of the public methods to be factored into a smaller number
     * of internal methods (although sadly not so for the five
     * variants of put-related operations). The validation-based
     * approach explained below leads to a lot of code sprawl because
     * retry-control precludes factoring into smaller methods.
     *
     * The table is lazily initialized to a power-of-two size upon the
     * first insertion.  Each bin in the table normally contains a
     * list of Nodes (most often, the list has only zero or one Node).
     * Table accesses require volatile/atomic reads, writes, and
     * CASes.  Because there is no other way to arrange this without
     * adding further indirections, we use intrinsics
     * (sun.misc.Unsafe) operations.  The lists of nodes within bins
     * are always accurately traversable under volatile reads, so long
     * as lookups check hash code and non-nullness of value before
     * checking key equality.
     *
     * We use the top two bits of Node hash fields for control
     * purposes -- they are available anyway because of addressing
     * constraints.  As explained further below, these top bits are
     * used as follows:
     *  00 - Normal
     *  01 - Locked
     *  11 - Locked and may have a thread waiting for lock
     *  10 - Node is a forwarding node
     *
     * The lower 30 bits of each Node's hash field contain a
     * transformation of the key's hash code, except for forwarding
     * nodes, for which the lower bits are zero (and so always have
     * hash field == MOVED).
     *
     * Insertion (via put or its variants) of the first node in an
     * empty bin is performed by just CASing it to the bin.  This is
     * by far the most common case for put operations under most
     * key/hash distributions.  Other update operations (insert,
     * delete, and replace) require locks.  We do not want to waste
     * the space required to associate a distinct lock object with
     * each bin, so instead use the first node of a bin list itself as
     * a lock. Blocking support for these locks relies on the builtin
     * "synchronized" monitors.  However, we also need a tryLock
     * construction, so we overlay these by using bits of the Node
     * hash field for lock control (see above), and so normally use
     * builtin monitors only for blocking and signalling using
     * wait/notifyAll constructions. See Node.tryAwaitLock.
     *
     * Using the first node of a list as a lock does not by itself
     * suffice though: When a node is locked, any update must first
     * validate that it is still the first node after locking it, and
     * retry if not. Because new nodes are always appended to lists,
     * once a node is first in a bin, it remains first until deleted
     * or the bin becomes invalidated (upon resizing).  However,
     * operations that only conditionally update may inspect nodes
     * until the point of update. This is a converse of sorts to the
     * lazy locking technique described by Herlihy & Shavit.
     *
     * The main disadvantage of per-bin locks is that other update
     * operations on other nodes in a bin list protected by the same
     * lock can stall, for example when user equals() or mapping
     * functions take a long time.  However, statistically, under
     * random hash codes, this is not a common problem.  Ideally, the
     * frequency of nodes in bins follows a Poisson distribution
     * (http://en.wikipedia.org/wiki/Poisson_distribution) with a
     * parameter of about 0.5 on average, given the resizing threshold
     * of 0.75, although with a large variance because of resizing
     * granularity. Ignoring variance, the expected occurrences of
     * list size k are (exp(-0.5) * pow(0.5, k) / factorial(k)). The
     * first values are:
     *
     * 0:    0.60653066
     * 1:    0.30326533
     * 2:    0.07581633
     * 3:    0.01263606
     * 4:    0.00157952
     * 5:    0.00015795
     * 6:    0.00001316
     * 7:    0.00000094
     * 8:    0.00000006
     * more: less than 1 in ten million
     *
     * Lock contention probability for two threads accessing distinct
     * elements is roughly 1 / (8 * #elements) under random hashes.
     *
     * Actual hash code distributions encountered in practice
     * sometimes deviate significantly from uniform randomness.  This
     * includes the case when N > (1<<30), so some keys MUST collide.
     * Similarly for dumb or hostile usages in which multiple keys are
     * designed to have identical hash codes. Also, although we guard
     * against the worst effects of this (see method spread), sets of
     * hashes may differ only in bits that do not impact their bin
     * index for a given power-of-two mask.  So we use a secondary
     * strategy that applies when the number of nodes in a bin exceeds
     * a threshold, and at least one of the keys implements
     * Comparable.  These TreeBins use a balanced tree to hold nodes
     * (a specialized form of red-black trees), bounding search time
     * to O(log N).  Each search step in a TreeBin is around twice as
     * slow as in a regular list, but given that N cannot exceed
     * (1<<64) (before running out of addresses) this bounds search
     * steps, lock hold times, etc, to reasonable constants (roughly
     * 100 nodes inspected per operation worst case) so long as keys
     * are Comparable (which is very common -- String, Long, etc).
     * TreeBin nodes (TreeNodes) also maintain the same "next"
     * traversal pointers as regular nodes, so can be traversed in
     * iterators in the same way.
     *
     * The table is resized when occupancy exceeds a percentage
     * threshold (nominally, 0.75, but see below).  Only a single
     * thread performs the resize (using field "sizeCtl", to arrange
     * exclusion), but the table otherwise remains usable for reads
     * and updates. Resizing proceeds by transferring bins, one by
     * one, from the table to the next table.  Because we are using
     * power-of-two expansion, the elements from each bin must either
     * stay at same index, or move with a power of two offset. We
     * eliminate unnecessary node creation by catching cases where old
     * nodes can be reused because their next fields won't change.  On
     * average, only about one-sixth of them need cloning when a table
     * doubles. The nodes they replace will be garbage collectable as
     * soon as they are no longer referenced by any reader thread that
     * may be in the midst of concurrently traversing table.  Upon
     * transfer, the old table bin contains only a special forwarding
     * node (with hash field "MOVED") that contains the next table as
     * its key. On encountering a forwarding node, access and update
     * operations restart, using the new table.
     *
     * Each bin transfer requires its bin lock. However, unlike other
     * cases, a transfer can skip a bin if it fails to acquire its
     * lock, and revisit it later (unless it is a TreeBin). Method
     * rebuild maintains a buffer of TRANSFER_BUFFER_SIZE bins that
     * have been skipped because of failure to acquire a lock, and
     * blocks only if none are available (i.e., only very rarely).
     * The transfer operation must also ensure that all accessible
     * bins in both the old and new table are usable by any traversal.
     * When there are no lock acquisition failures, this is arranged
     * simply by proceeding from the last bin (table.length - 1) up
     * towards the first.  Upon seeing a forwarding node, traversals
     * (see class InternalIterator) arrange to move to the new table
     * without revisiting nodes.  However, when any node is skipped
     * during a transfer, all earlier table bins may have become
     * visible, so are initialized with a reverse-forwarding node back
     * to the old table until the new ones are established. (This
     * sometimes requires transiently locking a forwarding node, which
     * is possible under the above encoding.) These more expensive
     * mechanics trigger only when necessary.
     *
     * The traversal scheme also applies to partial traversals of
     * ranges of bins (via an alternate InternalIterator constructor)
     * to support partitioned aggregate operations (that are not
     * otherwise implemented yet).  Also, read-only operations give up
     * if ever forwarded to a null table, which provides support for
     * shutdown-style clearing, which is also not currently
     * implemented.
     *
     * Lazy table initialization minimizes footprint until first use,
     * and also avoids resizings when the first operation is from a
     * putAll, constructor with map argument, or deserialization.
     * These cases attempt to override the initial capacity settings,
     * but harmlessly fail to take effect in cases of races.
     *
     * The element count is maintained using a LongAdder, which avoids
     * contention on updates but can encounter cache thrashing if read
     * too frequently during concurrent access. To avoid reading so
     * often, resizing is attempted either when a bin lock is
     * contended, or upon adding to a bin already holding two or more
     * nodes (checked before adding in the xIfAbsent methods, after
     * adding in others). Under uniform hash distributions, the
     * probability of this occurring at threshold is around 13%,
     * meaning that only about 1 in 8 puts check threshold (and after
     * resizing, many fewer do so). But this approximation has high
     * variance for small table sizes, so we check on any collision
     * for sizes <= 64. The bulk putAll operation further reduces
     * contention by only committing count updates upon these size
     * checks.
     *
     * Maintaining API and serialization compatibility with previous
     * versions of this class introduces several oddities. Mainly: We
     * leave untouched but unused constructor arguments refering to
     * concurrencyLevel. We accept a loadFactor constructor argument,
     * but apply it only to initial table capacity (which is the only
     * time that we can guarantee to honor it.) We also declare an
     * unused "Segment" class that is instantiated in minimal form
     * only when serializing.
     */

    /* ---------------- Constants -------------- */

    /**
     * The largest possible table capacity.  This value must be
     * exactly 1<<30 to stay within Java array allocation and indexing
     * bounds for power of two table sizes, and is further required
     * because the top two bits of 32bit hash fields are used for
     * control purposes.
     */
    private static final int MAXIMUM_CAPACITY = 1 << 30;

    /**
     * The default initial table capacity.  Must be a power of 2
     * (i.e., at least 1) and at most MAXIMUM_CAPACITY.
     */
    private static final int DEFAULT_CAPACITY = 16;

    /**
     * The largest possible (non-power of two) array size.
     * Needed by toArray and related methods.
     */
    static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    /**
     * The default concurrency level for this table. Unused but
     * defined for compatibility with previous versions of this class.
     */
    private static final int DEFAULT_CONCURRENCY_LEVEL = 16;

    /**
     * The load factor for this table. Overrides of this value in
     * constructors affect only the initial table capacity.  The
     * actual floating point value isn't normally used -- it is
     * simpler to use expressions such as {@code n - (n >>> 2)} for
     * the associated resizing threshold.
     */
    private static final float LOAD_FACTOR = 0.75f;

    /**
     * The buffer size for skipped bins during transfers. The
     * value is arbitrary but should be large enough to avoid
     * most locking stalls during resizes.
     */
    private static final int TRANSFER_BUFFER_SIZE = 32;

    /**
     * The bin count threshold for using a tree rather than list for a
     * bin.  The value reflects the approximate break-even point for
     * using tree-based operations.
     */
    private static final int TREE_THRESHOLD = 8;

    /*
     * Encodings for special uses of Node hash fields. See above for
     * explanation.
     */
    static final int MOVED     = 0x80000000; // hash field for forwarding nodes
    static final int LOCKED    = 0x40000000; // set/tested only as a bit
    static final int WAITING   = 0xc0000000; // both bits set/tested together
    static final int HASH_BITS = 0x3fffffff; // usable bits of normal node hash

    /* ---------------- Fields -------------- */

    /**
     * The array of bins. Lazily initialized upon first insertion.
     * Size is always a power of two. Accessed directly by iterators.
     */
    transient volatile Node[] table;

    /**
     * The counter maintaining number of elements.
     */
    private transient final LongAdder counter;

    /**
     * Table initialization and resizing control.  When negative, the
     * table is being initialized or resized. Otherwise, when table is
     * null, holds the initial table size to use upon creation, or 0
     * for default. After initialization, holds the next element count
     * value upon which to resize the table.
     */
    private transient volatile int sizeCtl;

    // views
    private transient KeySet<K,V> keySet;
    private transient Values<K,V> values;
    private transient EntrySet<K,V> entrySet;

    /** For serialization compatibility. Null unless serialized; see below */
    private Segment<K,V>[] segments;

    /* ---------------- Table element access -------------- */

    /*
     * Volatile access methods are used for table elements as well as
     * elements of in-progress next table while resizing.  Uses are
     * null checked by callers, and implicitly bounds-checked, relying
     * on the invariants that tab arrays have non-zero size, and all
     * indices are masked with (tab.length - 1) which is never
     * negative and always less than length. Note that, to be correct
     * wrt arbitrary concurrency errors by users, bounds checks must
     * operate on local variables, which accounts for some odd-looking
     * inline assignments below.
     */

    static final Node tabAt(Node[] tab, int i) { // used by InternalIterator
        return (Node)UNSAFE.getObjectVolatile(tab, ((long)i<<ASHIFT)+ABASE);
    }

    private static final boolean casTabAt(Node[] tab, int i, Node c, Node v) {
        return UNSAFE.compareAndSwapObject(tab, ((long)i<<ASHIFT)+ABASE, c, v);
    }

    private static final void setTabAt(Node[] tab, int i, Node v) {
        UNSAFE.putObjectVolatile(tab, ((long)i<<ASHIFT)+ABASE, v);
    }

    /* ---------------- Nodes -------------- */

    /**
     * Key-value entry. Note that this is never exported out as a
     * user-visible Map.Entry (see WriteThroughEntry and SnapshotEntry
     * below). Nodes with a hash field of MOVED are special, and do
     * not contain user keys or values.  Otherwise, keys are never
     * null, and null val fields indicate that a node is in the
     * process of being deleted or created. For purposes of read-only
     * access, a key may be read before a val, but can only be used
     * after checking val to be non-null.
     */
    static class Node {
        volatile int hash;
        final Object key;
        volatile Object val;
        volatile Node next;

        Node(int hash, Object key, Object val, Node next) {
            this.hash = hash;
            this.key = key;
            this.val = val;
            this.next = next;
        }

        /** CompareAndSet the hash field */
        final boolean casHash(int cmp, int val) {
            return UNSAFE.compareAndSwapInt(this, hashOffset, cmp, val);
        }

        /** The number of spins before blocking for a lock */
        static final int MAX_SPINS =
            Runtime.getRuntime().availableProcessors() > 1 ? 64 : 1;

        /**
         * Spins a while if LOCKED bit set and this node is the first
         * of its bin, and then sets WAITING bits on hash field and
         * blocks (once) if they are still set.  It is OK for this
         * method to return even if lock is not available upon exit,
         * which enables these simple single-wait mechanics.
         *
         * The corresponding signalling operation is performed within
         * callers: Upon detecting that WAITING has been set when
         * unlocking lock (via a failed CAS from non-waiting LOCKED
         * state), unlockers acquire the sync lock and perform a
         * notifyAll.
         */
        final void tryAwaitLock(Node[] tab, int i) {
            if (tab != null && i >= 0 && i < tab.length) { // bounds check
                int r = ThreadLocalRandom.current().nextInt(); // randomize spins
                int spins = MAX_SPINS, h;
                while (tabAt(tab, i) == this && ((h = hash) & LOCKED) != 0) {
                    if (spins >= 0) {
                        r ^= r << 1; r ^= r >>> 3; r ^= r << 10; // xorshift
                        if (r >= 0 && --spins == 0)
                            Thread.yield();  // yield before block
                    }
                    else if (casHash(h, h | WAITING)) {
                        synchronized (this) {
                            if (tabAt(tab, i) == this &&
                                (hash & WAITING) == WAITING) {
                                try {
                                    wait();
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                }
                            }
                            else
                                notifyAll(); // possibly won race vs signaller
                        }
                        break;
                    }
                }
            }
        }

        // Unsafe mechanics for casHash
        private static final sun.misc.Unsafe UNSAFE;
        private static final long hashOffset;

        static {
            try {
                UNSAFE = getUnsafe();
                Class<?> k = Node.class;
                hashOffset = UNSAFE.objectFieldOffset
                    (k.getDeclaredField("hash"));
            } catch (Exception e) {
                throw new Error(e);
            }
        }
    }

    /* ---------------- TreeBins -------------- */

    /**
     * Nodes for use in TreeBins
     */
    static final class TreeNode extends Node {
        TreeNode parent;  // red-black tree links
        TreeNode left;
        TreeNode right;
        TreeNode prev;    // needed to unlink next upon deletion
        boolean red;

        TreeNode(int hash, Object key, Object val, Node next, TreeNode parent) {
            super(hash, key, val, next);
            this.parent = parent;
        }
    }

    /**
     * A specialized form of red-black tree for use in bins
     * whose size exceeds a threshold.
     *
     * TreeBins use a special form of comparison for search and
     * related operations (which is the main reason we cannot use
     * existing collections such as TreeMaps). TreeBins contain
     * Comparable elements, but may contain others, as well as
     * elements that are Comparable but not necessarily Comparable<T>
     * for the same T, so we cannot invoke compareTo among them. To
     * handle this, the tree is ordered primarily by hash value, then
     * by getClass().getName() order, and then by Comparator order
     * among elements of the same class.  On lookup at a node, if
     * non-Comparable, both left and right children may need to be
     * searched in the case of tied hash values. (This corresponds to
     * the full list search that would be necessary if all elements
     * were non-Comparable and had tied hashes.)
     *
     * TreeBins also maintain a separate locking discipline than
     * regular bins. Because they are forwarded via special MOVED
     * nodes at bin heads (which can never change once established),
     * we cannot use use those nodes as locks. Instead, TreeBin
     * extends AbstractQueuedSynchronizer to support a simple form of
     * read-write lock. For update operations and table validation,
     * the exclusive form of lock behaves in the same way as bin-head
     * locks. However, lookups use shared read-lock mechanics to allow
     * multiple readers in the absence of writers.  Additionally,
     * these lookups do not ever block: While the lock is not
     * available, they proceed along the slow traversal path (via
     * next-pointers) until the lock becomes available or the list is
     * exhausted, whichever comes first. (These cases are not fast,
     * but maximize aggregate expected throughput.)  The AQS mechanics
     * for doing this are straightforward.  The lock state is held as
     * AQS getState().  Read counts are negative; the write count (1)
     * is positive.  There are no signalling preferences among readers
     * and writers. Since we don't need to export full Lock API, we
     * just override the minimal AQS methods and use them directly.
     */
    static final class TreeBin extends AbstractQueuedSynchronizer {
        private static final long serialVersionUID = 2249069246763182397L;
        TreeNode root;  // root of tree
        TreeNode first; // head of next-pointer list

        /* AQS overrides */
        public final boolean isHeldExclusively() { return getState() > 0; }
        public final boolean tryAcquire(int ignore) {
            if (compareAndSetState(0, 1)) {
                setExclusiveOwnerThread(Thread.currentThread());
                return true;
            }
            return false;
        }
        public final boolean tryRelease(int ignore) {
            setExclusiveOwnerThread(null);
            setState(0);
            return true;
        }
        public final int tryAcquireShared(int ignore) {
            for (int c;;) {
                if ((c = getState()) > 0)
                    return -1;
                if (compareAndSetState(c, c -1))
                    return 1;
            }
        }
        public final boolean tryReleaseShared(int ignore) {
            int c;
            do {} while (!compareAndSetState(c = getState(), c + 1));
            return c == -1;
        }

        /**
         * Return the TreeNode (or null if not found) for the given key
         * starting at given root.
         */
        @SuppressWarnings("unchecked") // suppress Comparable cast warning
        final TreeNode getTreeNode(int h, Object k, TreeNode p) {
            Class<?> c = k.getClass();
            while (p != null) {
                int dir, ph;  Object pk; Class<?> pc; TreeNode r;
                if (h < (ph = p.hash))
                    dir = -1;
                else if (h > ph)
                    dir = 1;
                else if ((pk = p.key) == k || k.equals(pk))
                    return p;
                else if (c != (pc = pk.getClass()))
                    dir = c.getName().compareTo(pc.getName());
                else if (k instanceof Comparable)
                    dir = ((Comparable)k).compareTo((Comparable)pk);
                else
                    dir = 0;
                TreeNode pr = p.right;
                if (dir > 0)
                    p = pr;
                else if (dir == 0 && pr != null && h >= pr.hash &&
                         (r = getTreeNode(h, k, pr)) != null)
                    return r;
                else
                    p = p.left;
            }
            return null;
        }

        /**
         * Wrapper for getTreeNode used by CHM.get. Tries to obtain
         * read-lock to call getTreeNode, but during failure to get
         * lock, searches along next links.
         */
        final Object getValue(int h, Object k) {
            Node r = null;
            int c = getState(); // Must read lock state first
            for (Node e = first; e != null; e = e.next) {
                if (c <= 0 && compareAndSetState(c, c - 1)) {
                    try {
                        r = getTreeNode(h, k, root);
                    } finally {
                        releaseShared(0);
                    }
                    break;
                }
                else if ((e.hash & HASH_BITS) == h && k.equals(e.key)) {
                    r = e;
                    break;
                }
                else
                    c = getState();
            }
            return r == null ? null : r.val;
        }

        /**
         * Find or add a node
         * @return null if added
         */
        @SuppressWarnings("unchecked") // suppress Comparable cast warning
        final TreeNode putTreeNode(int h, Object k, Object v) {
            Class<?> c = k.getClass();
            TreeNode p = root;
            int dir = 0;
            if (p != null) {
                for (;;) {
                    int ph;  Object pk; Class<?> pc; TreeNode r;
                    if (h < (ph = p.hash))
                        dir = -1;
                    else if (h > ph)
                        dir = 1;
                    else if ((pk = p.key) == k || k.equals(pk))
                        return p;
                    else if (c != (pc = (pk = p.key).getClass()))
                        dir = c.getName().compareTo(pc.getName());
                    else if (k instanceof Comparable)
                        dir = ((Comparable)k).compareTo((Comparable)pk);
                    else
                        dir = 0;
                    TreeNode pr = p.right, pl;
                    if (dir > 0) {
                        if (pr == null)
                            break;
                        p = pr;
                    }
                    else if (dir == 0 && pr != null && h >= pr.hash &&
                             (r = getTreeNode(h, k, pr)) != null)
                        return r;
                    else if ((pl = p.left) == null)
                        break;
                    else
                        p = pl;
                }
            }
            TreeNode f = first;
            TreeNode r = first = new TreeNode(h, k, v, f, p);
            if (p == null)
                root = r;
            else {
                if (dir <= 0)
                    p.left = r;
                else
                    p.right = r;
                if (f != null)
                    f.prev = r;
                fixAfterInsertion(r);
            }
            return null;
        }

        /**
         * Removes the given node, that must be present before this
         * call.  This is messier than typical red-black deletion code
         * because we cannot swap the contents of an interior node
         * with a leaf successor that is pinned by "next" pointers
         * that are accessible independently of lock. So instead we
         * swap the tree linkages.
         */
        final void deleteTreeNode(TreeNode p) {
            TreeNode next = (TreeNode)p.next; // unlink traversal pointers
            TreeNode pred = p.prev;
            if (pred == null)
                first = next;
            else
                pred.next = next;
            if (next != null)
                next.prev = pred;
            TreeNode replacement;
            TreeNode pl = p.left;
            TreeNode pr = p.right;
            if (pl != null && pr != null) {
                TreeNode s = pr;
                while (s.left != null) // find successor
                    s = s.left;
                boolean c = s.red; s.red = p.red; p.red = c; // swap colors
                TreeNode sr = s.right;
                TreeNode pp = p.parent;
                if (s == pr) { // p was s's direct parent
                    p.parent = s;
                    s.right = p;
                }
                else {
                    TreeNode sp = s.parent;
                    if ((p.parent = sp) != null) {
                        if (s == sp.left)
                            sp.left = p;
                        else
                            sp.right = p;
                    }
                    if ((s.right = pr) != null)
                        pr.parent = s;
                }
                p.left = null;
                if ((p.right = sr) != null)
                    sr.parent = p;
                if ((s.left = pl) != null)
                    pl.parent = s;
                if ((s.parent = pp) == null)
                    root = s;
                else if (p == pp.left)
                    pp.left = s;
                else
                    pp.right = s;
                replacement = sr;
            }
            else
                replacement = (pl != null) ? pl : pr;
            TreeNode pp = p.parent;
            if (replacement == null) {
                if (pp == null) {
                    root = null;
                    return;
                }
                replacement = p;
            }
            else {
                replacement.parent = pp;
                if (pp == null)
                    root = replacement;
                else if (p == pp.left)
                    pp.left = replacement;
                else
                    pp.right = replacement;
                p.left = p.right = p.parent = null;
            }
            if (!p.red)
                fixAfterDeletion(replacement);
            if (p == replacement && (pp = p.parent) != null) {
                if (p == pp.left) // detach pointers
                    pp.left = null;
                else if (p == pp.right)
                    pp.right = null;
                p.parent = null;
            }
        }

        // CLR code updated from pre-jdk-collections version at
        // http://gee.cs.oswego.edu/dl/classes/collections/RBCell.java

        /** From CLR */
        private void rotateLeft(TreeNode p) {
            if (p != null) {
                TreeNode r = p.right, pp, rl;
                if ((rl = p.right = r.left) != null)
                    rl.parent = p;
                if ((pp = r.parent = p.parent) == null)
                    root = r;
                else if (pp.left == p)
                    pp.left = r;
                else
                    pp.right = r;
                r.left = p;
                p.parent = r;
            }
        }

        /** From CLR */
        private void rotateRight(TreeNode p) {
            if (p != null) {
                TreeNode l = p.left, pp, lr;
                if ((lr = p.left = l.right) != null)
                    lr.parent = p;
                if ((pp = l.parent = p.parent) == null)
                    root = l;
                else if (pp.right == p)
                    pp.right = l;
                else
                    pp.left = l;
                l.right = p;
                p.parent = l;
            }
        }

        /** From CLR */
        private void fixAfterInsertion(TreeNode x) {
            x.red = true;
            TreeNode xp, xpp;
            while (x != null && (xp = x.parent) != null && xp.red &&
                   (xpp = xp.parent) != null) {
                TreeNode xppl = xpp.left;
                if (xp == xppl) {
                    TreeNode y = xpp.right;
                    if (y != null && y.red) {
                        y.red = false;
                        xp.red = false;
                        xpp.red = true;
                        x = xpp;
                    }
                    else {
                        if (x == xp.right) {
                            x = xp;
                            rotateLeft(x);
                            xpp = (xp = x.parent) == null ? null : xp.parent;
                        }
                        if (xp != null) {
                            xp.red = false;
                            if (xpp != null) {
                                xpp.red = true;
                                rotateRight(xpp);
                            }
                        }
                    }
                }
                else {
                    TreeNode y = xppl;
                    if (y != null && y.red) {
                        y.red = false;
                        xp.red = false;
                        xpp.red = true;
                        x = xpp;
                    }
                    else {
                        if (x == xp.left) {
                            x = xp;
                            rotateRight(x);
                            xpp = (xp = x.parent) == null ? null : xp.parent;
                        }
                        if (xp != null) {
                            xp.red = false;
                            if (xpp != null) {
                                xpp.red = true;
                                rotateLeft(xpp);
                            }
                        }
                    }
                }
            }
            TreeNode r = root;
            if (r != null && r.red)
                r.red = false;
        }

        /** From CLR */
        private void fixAfterDeletion(TreeNode x) {
            while (x != null) {
                TreeNode xp, xpl;
                if (x.red || (xp = x.parent) == null) {
                    x.red = false;
                    break;
                }
                if (x == (xpl = xp.left)) {
                    TreeNode sib = xp.right;
                    if (sib != null && sib.red) {
                        sib.red = false;
                        xp.red = true;
                        rotateLeft(xp);
                        sib = (xp = x.parent) == null ? null : xp.right;
                    }
                    if (sib == null)
                        x = xp;
                    else {
                        TreeNode sl = sib.left, sr = sib.right;
                        if ((sr == null || !sr.red) &&
                            (sl == null || !sl.red)) {
                            sib.red = true;
                            x = xp;
                        }
                        else {
                            if (sr == null || !sr.red) {
                                if (sl != null)
                                    sl.red = false;
                                sib.red = true;
                                rotateRight(sib);
                                sib = (xp = x.parent) == null ? null : xp.right;
                            }
                            if (sib != null) {
                                sib.red = (xp == null) ? false : xp.red;
                                if ((sr = sib.right) != null)
                                    sr.red = false;
                            }
                            if (xp != null) {
                                xp.red = false;
                                rotateLeft(xp);
                            }
                            x = root;
                        }
                    }
                }
                else { // symmetric
                    TreeNode sib = xpl;
                    if (sib != null && sib.red) {
                        sib.red = false;
                        xp.red = true;
                        rotateRight(xp);
                        sib = (xp = x.parent) == null ? null : xp.left;
                    }
                    if (sib == null)
                        x = xp;
                    else {
                        TreeNode sl = sib.left, sr = sib.right;
                        if ((sl == null || !sl.red) &&
                            (sr == null || !sr.red)) {
                            sib.red = true;
                            x = xp;
                        }
                        else {
                            if (sl == null || !sl.red) {
                                if (sr != null)
                                    sr.red = false;
                                sib.red = true;
                                rotateLeft(sib);
                                sib = (xp = x.parent) == null ? null : xp.left;
                            }
                            if (sib != null) {
                                sib.red = (xp == null) ? false : xp.red;
                                if ((sl = sib.left) != null)
                                    sl.red = false;
                            }
                            if (xp != null) {
                                xp.red = false;
                                rotateRight(xp);
                            }
                            x = root;
                        }
                    }
                }
            }
        }
    }

    /* ---------------- Collision reduction methods -------------- */

    /**
     * Spreads higher bits to lower, and also forces top 2 bits to 0.
     * Because the table uses power-of-two masking, sets of hashes
     * that vary only in bits above the current mask will always
     * collide. (Among known examples are sets of Float keys holding
     * consecutive whole numbers in small tables.)  To counter this,
     * we apply a transform that spreads the impact of higher bits
     * downward. There is a tradeoff between speed, utility, and
     * quality of bit-spreading. Because many common sets of hashes
     * are already reasonably distributed across bits (so don't benefit
     * from spreading), and because we use trees to handle large sets
     * of collisions in bins, we don't need excessively high quality.
     */
    private static final int spread(int h) {
        h ^= (h >>> 18) ^ (h >>> 12);
        return (h ^ (h >>> 10)) & HASH_BITS;
    }

    /**
     * Replaces a list bin with a tree bin. Call only when locked.
     * Fails to replace if the given key is non-comparable or table
     * is, or needs, resizing.
     */
    private final void replaceWithTreeBin(Node[] tab, int index, Object key) {
        if ((key instanceof Comparable) &&
            (tab.length >= MAXIMUM_CAPACITY || counter.sum() < (long)sizeCtl)) {
            TreeBin t = new TreeBin();
            for (Node e = tabAt(tab, index); e != null; e = e.next)
                t.putTreeNode(e.hash & HASH_BITS, e.key, e.val);
            setTabAt(tab, index, new Node(MOVED, t, null, null));
        }
    }

    /* ---------------- Internal access and update methods -------------- */

    /** Implementation for get and containsKey */
    private final Object internalGet(Object k) {
        int h = spread(k.hashCode());
        retry: for (Node[] tab = table; tab != null;) {
            Node e, p; Object ek, ev; int eh;      // locals to read fields once
            for (e = tabAt(tab, (tab.length - 1) & h); e != null; e = e.next) {
                if ((eh = e.hash) == MOVED) {
                    if ((ek = e.key) instanceof TreeBin)  // search TreeBin
                        return ((TreeBin)ek).getValue(h, k);
                    else {                        // restart with new table
                        tab = (Node[])ek;
                        continue retry;
                    }
                }
                else if ((eh & HASH_BITS) == h && (ev = e.val) != null &&
                         ((ek = e.key) == k || k.equals(ek)))
                    return ev;
            }
            break;
        }
        return null;
    }

    /**
     * Implementation for the four public remove/replace methods:
     * Replaces node value with v, conditional upon match of cv if
     * non-null.  If resulting value is null, delete.
     */
    private final Object internalReplace(Object k, Object v, Object cv) {
        int h = spread(k.hashCode());
        Object oldVal = null;
        for (Node[] tab = table;;) {
            Node f; int i, fh; Object fk;
            if (tab == null ||
                (f = tabAt(tab, i = (tab.length - 1) & h)) == null)
                break;
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    boolean validated = false;
                    boolean deleted = false;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            validated = true;
                            TreeNode p = t.getTreeNode(h, k, t.root);
                            if (p != null) {
                                Object pv = p.val;
                                if (cv == null || cv == pv || cv.equals(pv)) {
                                    oldVal = pv;
                                    if ((p.val = v) == null) {
                                        deleted = true;
                                        t.deleteTreeNode(p);
                                    }
                                }
                            }
                        }
                    } finally {
                        t.release(0);
                    }
                    if (validated) {
                        if (deleted)
                            counter.add(-1L);
                        break;
                    }
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & HASH_BITS) != h && f.next == null) // precheck
                break;                          // rules out possible existence
            else if ((fh & LOCKED) != 0) {
                checkForResize();               // try resizing if can't get lock
                f.tryAwaitLock(tab, i);
            }
            else if (f.casHash(fh, fh | LOCKED)) {
                boolean validated = false;
                boolean deleted = false;
                try {
                    if (tabAt(tab, i) == f) {
                        validated = true;
                        for (Node e = f, pred = null;;) {
                            Object ek, ev;
                            if ((e.hash & HASH_BITS) == h &&
                                ((ev = e.val) != null) &&
                                ((ek = e.key) == k || k.equals(ek))) {
                                if (cv == null || cv == ev || cv.equals(ev)) {
                                    oldVal = ev;
                                    if ((e.val = v) == null) {
                                        deleted = true;
                                        Node en = e.next;
                                        if (pred != null)
                                            pred.next = en;
                                        else
                                            setTabAt(tab, i, en);
                                    }
                                }
                                break;
                            }
                            pred = e;
                            if ((e = e.next) == null)
                                break;
                        }
                    }
                } finally {
                    if (!f.casHash(fh | LOCKED, fh)) {
                        f.hash = fh;
                        synchronized (f) { f.notifyAll(); };
                    }
                }
                if (validated) {
                    if (deleted)
                        counter.add(-1L);
                    break;
                }
            }
        }
        return oldVal;
    }

    /*
     * Internal versions of the five insertion methods, each a
     * little more complicated than the last. All have
     * the same basic structure as the first (internalPut):
     *  1. If table uninitialized, create
     *  2. If bin empty, try to CAS new node
     *  3. If bin stale, use new table
     *  4. if bin converted to TreeBin, validate and relay to TreeBin methods
     *  5. Lock and validate; if valid, scan and add or update
     *
     * The others interweave other checks and/or alternative actions:
     *  * Plain put checks for and performs resize after insertion.
     *  * putIfAbsent prescans for mapping without lock (and fails to add
     *    if present), which also makes pre-emptive resize checks worthwhile.
     *  * computeIfAbsent extends form used in putIfAbsent with additional
     *    mechanics to deal with, calls, potential exceptions and null
     *    returns from function call.
     *  * compute uses the same function-call mechanics, but without
     *    the prescans
     *  * putAll attempts to pre-allocate enough table space
     *    and more lazily performs count updates and checks.
     *
     * Someday when details settle down a bit more, it might be worth
     * some factoring to reduce sprawl.
     */

    /** Implementation for put */
    private final Object internalPut(Object k, Object v) {
        int h = spread(k.hashCode());
        int count = 0;
        for (Node[] tab = table;;) {
            int i; Node f; int fh; Object fk;
            if (tab == null)
                tab = initTable();
            else if ((f = tabAt(tab, i = (tab.length - 1) & h)) == null) {
                if (casTabAt(tab, i, null, new Node(h, k, v, null)))
                    break;                   // no lock when adding to empty bin
            }
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    Object oldVal = null;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 2;
                            TreeNode p = t.putTreeNode(h, k, v);
                            if (p != null) {
                                oldVal = p.val;
                                p.val = v;
                            }
                        }
                    } finally {
                        t.release(0);
                    }
                    if (count != 0) {
                        if (oldVal != null)
                            return oldVal;
                        break;
                    }
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & LOCKED) != 0) {
                checkForResize();
                f.tryAwaitLock(tab, i);
            }
            else if (f.casHash(fh, fh | LOCKED)) {
                Object oldVal = null;
                try {                        // needed in case equals() throws
                    if (tabAt(tab, i) == f) {
                        count = 1;
                        for (Node e = f;; ++count) {
                            Object ek, ev;
                            if ((e.hash & HASH_BITS) == h &&
                                (ev = e.val) != null &&
                                ((ek = e.key) == k || k.equals(ek))) {
                                oldVal = ev;
                                e.val = v;
                                break;
                            }
                            Node last = e;
                            if ((e = e.next) == null) {
                                last.next = new Node(h, k, v, null);
                                if (count >= TREE_THRESHOLD)
                                    replaceWithTreeBin(tab, i, k);
                                break;
                            }
                        }
                    }
                } finally {                  // unlock and signal if needed
                    if (!f.casHash(fh | LOCKED, fh)) {
                        f.hash = fh;
                        synchronized (f) { f.notifyAll(); };
                    }
                }
                if (count != 0) {
                    if (oldVal != null)
                        return oldVal;
                    if (tab.length <= 64)
                        count = 2;
                    break;
                }
            }
        }
        counter.add(1L);
        if (count > 1)
            checkForResize();
        return null;
    }

    /** Implementation for putIfAbsent */
    private final Object internalPutIfAbsent(Object k, Object v) {
        int h = spread(k.hashCode());
        int count = 0;
        for (Node[] tab = table;;) {
            int i; Node f; int fh; Object fk, fv;
            if (tab == null)
                tab = initTable();
            else if ((f = tabAt(tab, i = (tab.length - 1) & h)) == null) {
                if (casTabAt(tab, i, null, new Node(h, k, v, null)))
                    break;
            }
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    Object oldVal = null;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 2;
                            TreeNode p = t.putTreeNode(h, k, v);
                            if (p != null)
                                oldVal = p.val;
                        }
                    } finally {
                        t.release(0);
                    }
                    if (count != 0) {
                        if (oldVal != null)
                            return oldVal;
                        break;
                    }
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & HASH_BITS) == h && (fv = f.val) != null &&
                     ((fk = f.key) == k || k.equals(fk)))
                return fv;
            else {
                Node g = f.next;
                if (g != null) { // at least 2 nodes -- search and maybe resize
                    for (Node e = g;;) {
                        Object ek, ev;
                        if ((e.hash & HASH_BITS) == h && (ev = e.val) != null &&
                            ((ek = e.key) == k || k.equals(ek)))
                            return ev;
                        if ((e = e.next) == null) {
                            checkForResize();
                            break;
                        }
                    }
                }
                if (((fh = f.hash) & LOCKED) != 0) {
                    checkForResize();
                    f.tryAwaitLock(tab, i);
                }
                else if (tabAt(tab, i) == f && f.casHash(fh, fh | LOCKED)) {
                    Object oldVal = null;
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 1;
                            for (Node e = f;; ++count) {
                                Object ek, ev;
                                if ((e.hash & HASH_BITS) == h &&
                                    (ev = e.val) != null &&
                                    ((ek = e.key) == k || k.equals(ek))) {
                                    oldVal = ev;
                                    break;
                                }
                                Node last = e;
                                if ((e = e.next) == null) {
                                    last.next = new Node(h, k, v, null);
                                    if (count >= TREE_THRESHOLD)
                                        replaceWithTreeBin(tab, i, k);
                                    break;
                                }
                            }
                        }
                    } finally {
                        if (!f.casHash(fh | LOCKED, fh)) {
                            f.hash = fh;
                            synchronized (f) { f.notifyAll(); };
                        }
                    }
                    if (count != 0) {
                        if (oldVal != null)
                            return oldVal;
                        if (tab.length <= 64)
                            count = 2;
                        break;
                    }
                }
            }
        }
        counter.add(1L);
        if (count > 1)
            checkForResize();
        return null;
    }

    /** Implementation for computeIfAbsent */
    private final Object internalComputeIfAbsent(K k,
                                                 MappingFunction<? super K, ?> mf) {
        int h = spread(k.hashCode());
        Object val = null;
        int count = 0;
        for (Node[] tab = table;;) {
            Node f; int i, fh; Object fk, fv;
            if (tab == null)
                tab = initTable();
            else if ((f = tabAt(tab, i = (tab.length - 1) & h)) == null) {
                Node node = new Node(fh = h | LOCKED, k, null, null);
                if (casTabAt(tab, i, null, node)) {
                    count = 1;
                    try {
                        if ((val = mf.map(k)) != null)
                            node.val = val;
                    } finally {
                        if (val == null)
                            setTabAt(tab, i, null);
                        if (!node.casHash(fh, h)) {
                            node.hash = h;
                            synchronized (node) { node.notifyAll(); };
                        }
                    }
                }
                if (count != 0)
                    break;
            }
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    boolean added = false;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 1;
                            TreeNode p = t.getTreeNode(h, k, t.root);
                            if (p != null)
                                val = p.val;
                            else if ((val = mf.map(k)) != null) {
                                added = true;
                                count = 2;
                                t.putTreeNode(h, k, val);
                            }
                        }
                    } finally {
                        t.release(0);
                    }
                    if (count != 0) {
                        if (!added)
                            return val;
                        break;
                    }
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & HASH_BITS) == h && (fv = f.val) != null &&
                     ((fk = f.key) == k || k.equals(fk)))
                return fv;
            else {
                Node g = f.next;
                if (g != null) {
                    for (Node e = g;;) {
                        Object ek, ev;
                        if ((e.hash & HASH_BITS) == h && (ev = e.val) != null &&
                            ((ek = e.key) == k || k.equals(ek)))
                            return ev;
                        if ((e = e.next) == null) {
                            checkForResize();
                            break;
                        }
                    }
                }
                if (((fh = f.hash) & LOCKED) != 0) {
                    checkForResize();
                    f.tryAwaitLock(tab, i);
                }
                else if (tabAt(tab, i) == f && f.casHash(fh, fh | LOCKED)) {
                    boolean added = false;
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 1;
                            for (Node e = f;; ++count) {
                                Object ek, ev;
                                if ((e.hash & HASH_BITS) == h &&
                                    (ev = e.val) != null &&
                                    ((ek = e.key) == k || k.equals(ek))) {
                                    val = ev;
                                    break;
                                }
                                Node last = e;
                                if ((e = e.next) == null) {
                                    if ((val = mf.map(k)) != null) {
                                        added = true;
                                        last.next = new Node(h, k, val, null);
                                        if (count >= TREE_THRESHOLD)
                                            replaceWithTreeBin(tab, i, k);
                                    }
                                    break;
                                }
                            }
                        }
                    } finally {
                        if (!f.casHash(fh | LOCKED, fh)) {
                            f.hash = fh;
                            synchronized (f) { f.notifyAll(); };
                        }
                    }
                    if (count != 0) {
                        if (!added)
                            return val;
                        if (tab.length <= 64)
                            count = 2;
                        break;
                    }
                }
            }
        }
        if (val == null)
            throw new NullPointerException();
        counter.add(1L);
        if (count > 1)
            checkForResize();
        return val;
    }

    /** Implementation for compute */
    @SuppressWarnings("unchecked")
    private final Object internalCompute(K k,
                                         RemappingFunction<? super K, V> mf) {
        int h = spread(k.hashCode());
        Object val = null;
        boolean added = false;
        int count = 0;
        for (Node[] tab = table;;) {
            Node f; int i, fh; Object fk;
            if (tab == null)
                tab = initTable();
            else if ((f = tabAt(tab, i = (tab.length - 1) & h)) == null) {
                Node node = new Node(fh = h | LOCKED, k, null, null);
                if (casTabAt(tab, i, null, node)) {
                    try {
                        count = 1;
                        if ((val = mf.remap(k, null)) != null) {
                            node.val = val;
                            added = true;
                        }
                    } finally {
                        if (!added)
                            setTabAt(tab, i, null);
                        if (!node.casHash(fh, h)) {
                            node.hash = h;
                            synchronized (node) { node.notifyAll(); };
                        }
                    }
                }
                if (count != 0)
                    break;
            }
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            count = 1;
                            TreeNode p = t.getTreeNode(h, k, t.root);
                            Object pv = (p == null) ? null : p.val;
                            if ((val = mf.remap(k, (V)pv)) != null) {
                                if (p != null)
                                    p.val = val;
                                else {
                                    count = 2;
                                    added = true;
                                    t.putTreeNode(h, k, val);
                                }
                            }
                        }
                    } finally {
                        t.release(0);
                    }
                    if (count != 0)
                        break;
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & LOCKED) != 0) {
                checkForResize();
                f.tryAwaitLock(tab, i);
            }
            else if (f.casHash(fh, fh | LOCKED)) {
                try {
                    if (tabAt(tab, i) == f) {
                        count = 1;
                        for (Node e = f;; ++count) {
                            Object ek, ev;
                            if ((e.hash & HASH_BITS) == h &&
                                (ev = e.val) != null &&
                                ((ek = e.key) == k || k.equals(ek))) {
                                val = mf.remap(k, (V)ev);
                                if (val != null)
                                    e.val = val;
                                break;
                            }
                            Node last = e;
                            if ((e = e.next) == null) {
                                if ((val = mf.remap(k, null)) != null) {
                                    last.next = new Node(h, k, val, null);
                                    added = true;
                                    if (count >= TREE_THRESHOLD)
                                        replaceWithTreeBin(tab, i, k);
                                }
                                break;
                            }
                        }
                    }
                } finally {
                    if (!f.casHash(fh | LOCKED, fh)) {
                        f.hash = fh;
                        synchronized (f) { f.notifyAll(); };
                    }
                }
                if (count != 0) {
                    if (tab.length <= 64)
                        count = 2;
                    break;
                }
            }
        }
        if (val == null)
            throw new NullPointerException();
        if (added) {
            counter.add(1L);
            if (count > 1)
                checkForResize();
        }
        return val;
    }

    /** Implementation for putAll */
    private final void internalPutAll(Map<?, ?> m) {
        tryPresize(m.size());
        long delta = 0L;     // number of uncommitted additions
        boolean npe = false; // to throw exception on exit for nulls
        try {                // to clean up counts on other exceptions
            for (Map.Entry<?, ?> entry : m.entrySet()) {
                Object k, v;
                if (entry == null || (k = entry.getKey()) == null ||
                    (v = entry.getValue()) == null) {
                    npe = true;
                    break;
                }
                int h = spread(k.hashCode());
                for (Node[] tab = table;;) {
                    int i; Node f; int fh; Object fk;
                    if (tab == null)
                        tab = initTable();
                    else if ((f = tabAt(tab, i = (tab.length - 1) & h)) == null){
                        if (casTabAt(tab, i, null, new Node(h, k, v, null))) {
                            ++delta;
                            break;
                        }
                    }
                    else if ((fh = f.hash) == MOVED) {
                        if ((fk = f.key) instanceof TreeBin) {
                            TreeBin t = (TreeBin)fk;
                            boolean validated = false;
                            t.acquire(0);
                            try {
                                if (tabAt(tab, i) == f) {
                                    validated = true;
                                    TreeNode p = t.getTreeNode(h, k, t.root);
                                    if (p != null)
                                        p.val = v;
                                    else {
                                        t.putTreeNode(h, k, v);
                                        ++delta;
                                    }
                                }
                            } finally {
                                t.release(0);
                            }
                            if (validated)
                                break;
                        }
                        else
                            tab = (Node[])fk;
                    }
                    else if ((fh & LOCKED) != 0) {
                        counter.add(delta);
                        delta = 0L;
                        checkForResize();
                        f.tryAwaitLock(tab, i);
                    }
                    else if (f.casHash(fh, fh | LOCKED)) {
                        int count = 0;
                        try {
                            if (tabAt(tab, i) == f) {
                                count = 1;
                                for (Node e = f;; ++count) {
                                    Object ek, ev;
                                    if ((e.hash & HASH_BITS) == h &&
                                        (ev = e.val) != null &&
                                        ((ek = e.key) == k || k.equals(ek))) {
                                        e.val = v;
                                        break;
                                    }
                                    Node last = e;
                                    if ((e = e.next) == null) {
                                        ++delta;
                                        last.next = new Node(h, k, v, null);
                                        if (count >= TREE_THRESHOLD)
                                            replaceWithTreeBin(tab, i, k);
                                        break;
                                    }
                                }
                            }
                        } finally {
                            if (!f.casHash(fh | LOCKED, fh)) {
                                f.hash = fh;
                                synchronized (f) { f.notifyAll(); };
                            }
                        }
                        if (count != 0) {
                            if (count > 1) {
                                counter.add(delta);
                                delta = 0L;
                                checkForResize();
                            }
                            break;
                        }
                    }
                }
            }
        } finally {
            if (delta != 0)
                counter.add(delta);
        }
        if (npe)
            throw new NullPointerException();
    }

    /* ---------------- Table Initialization and Resizing -------------- */

    /**
     * Returns a power of two table size for the given desired capacity.
     * See Hackers Delight, sec 3.2
     */
    private static final int tableSizeFor(int c) {
        int n = c - 1;
        n |= n >>> 1;
        n |= n >>> 2;
        n |= n >>> 4;
        n |= n >>> 8;
        n |= n >>> 16;
        return (n < 0) ? 1 : (n >= MAXIMUM_CAPACITY) ? MAXIMUM_CAPACITY : n + 1;
    }

    /**
     * Initializes table, using the size recorded in sizeCtl.
     */
    private final Node[] initTable() {
        Node[] tab; int sc;
        while ((tab = table) == null) {
            if ((sc = sizeCtl) < 0)
                Thread.yield(); // lost initialization race; just spin
            else if (UNSAFE.compareAndSwapInt(this, sizeCtlOffset, sc, -1)) {
                try {
                    if ((tab = table) == null) {
                        int n = (sc > 0) ? sc : DEFAULT_CAPACITY;
                        tab = table = new Node[n];
                        sc = n - (n >>> 2);
                    }
                } finally {
                    sizeCtl = sc;
                }
                break;
            }
        }
        return tab;
    }

    /**
     * If table is too small and not already resizing, creates next
     * table and transfers bins.  Rechecks occupancy after a transfer
     * to see if another resize is already needed because resizings
     * are lagging additions.
     */
    private final void checkForResize() {
        Node[] tab; int n, sc;
        while ((tab = table) != null &&
               (n = tab.length) < MAXIMUM_CAPACITY &&
               (sc = sizeCtl) >= 0 && counter.sum() >= (long)sc &&
               UNSAFE.compareAndSwapInt(this, sizeCtlOffset, sc, -1)) {
            try {
                if (tab == table) {
                    table = rebuild(tab);
                    sc = (n << 1) - (n >>> 1);
                }
            } finally {
                sizeCtl = sc;
            }
        }
    }

    /**
     * Tries to presize table to accommodate the given number of elements.
     *
     * @param size number of elements (doesn't need to be perfectly accurate)
     */
    private final void tryPresize(int size) {
        int c = (size >= (MAXIMUM_CAPACITY >>> 1)) ? MAXIMUM_CAPACITY :
            tableSizeFor(size + (size >>> 1) + 1);
        int sc;
        while ((sc = sizeCtl) >= 0) {
            Node[] tab = table; int n;
            if (tab == null || (n = tab.length) == 0) {
                n = (sc > c) ? sc : c;
                if (UNSAFE.compareAndSwapInt(this, sizeCtlOffset, sc, -1)) {
                    try {
                        if (table == tab) {
                            table = new Node[n];
                            sc = n - (n >>> 2);
                        }
                    } finally {
                        sizeCtl = sc;
                    }
                }
            }
            else if (c <= sc || n >= MAXIMUM_CAPACITY)
                break;
            else if (UNSAFE.compareAndSwapInt(this, sizeCtlOffset, sc, -1)) {
                try {
                    if (table == tab) {
                        table = rebuild(tab);
                        sc = (n << 1) - (n >>> 1);
                    }
                } finally {
                    sizeCtl = sc;
                }
            }
        }
    }

    /*
     * Moves and/or copies the nodes in each bin to new table. See
     * above for explanation.
     *
     * @return the new table
     */
    private static final Node[] rebuild(Node[] tab) {
        int n = tab.length;
        Node[] nextTab = new Node[n << 1];
        Node fwd = new Node(MOVED, nextTab, null, null);
        int[] buffer = null;       // holds bins to revisit; null until needed
        Node rev = null;           // reverse forwarder; null until needed
        int nbuffered = 0;         // the number of bins in buffer list
        int bufferIndex = 0;       // buffer index of current buffered bin
        int bin = n - 1;           // current non-buffered bin or -1 if none

        for (int i = bin;;) {      // start upwards sweep
            int fh; Node f;
            if ((f = tabAt(tab, i)) == null) {
                if (bin >= 0) {    // no lock needed (or available)
                    if (!casTabAt(tab, i, f, fwd))
                        continue;
                }
                else {             // transiently use a locked forwarding node
                    Node g = new Node(MOVED|LOCKED, nextTab, null, null);
                    if (!casTabAt(tab, i, f, g))
                        continue;
                    setTabAt(nextTab, i, null);
                    setTabAt(nextTab, i + n, null);
                    setTabAt(tab, i, fwd);
                    if (!g.casHash(MOVED|LOCKED, MOVED)) {
                        g.hash = MOVED;
                        synchronized (g) { g.notifyAll(); }
                    }
                }
            }
            else if ((fh = f.hash) == MOVED) {
                Object fk = f.key;
                if (fk instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    boolean validated = false;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            validated = true;
                            splitTreeBin(nextTab, i, t);
                            setTabAt(tab, i, fwd);
                        }
                    } finally {
                        t.release(0);
                    }
                    if (!validated)
                        continue;
                }
            }
            else if ((fh & LOCKED) == 0 && f.casHash(fh, fh|LOCKED)) {
                boolean validated = false;
                try {              // split to lo and hi lists; copying as needed
                    if (tabAt(tab, i) == f) {
                        validated = true;
                        splitBin(nextTab, i, f);
                        setTabAt(tab, i, fwd);
                    }
                } finally {
                    if (!f.casHash(fh | LOCKED, fh)) {
                        f.hash = fh;
                        synchronized (f) { f.notifyAll(); };
                    }
                }
                if (!validated)
                    continue;
            }
            else {
                if (buffer == null) // initialize buffer for revisits
                    buffer = new int[TRANSFER_BUFFER_SIZE];
                if (bin < 0 && bufferIndex > 0) {
                    int j = buffer[--bufferIndex];
                    buffer[bufferIndex] = i;
                    i = j;         // swap with another bin
                    continue;
                }
                if (bin < 0 || nbuffered >= TRANSFER_BUFFER_SIZE) {
                    f.tryAwaitLock(tab, i);
                    continue;      // no other options -- block
                }
                if (rev == null)   // initialize reverse-forwarder
                    rev = new Node(MOVED, tab, null, null);
                if (tabAt(tab, i) != f || (f.hash & LOCKED) == 0)
                    continue;      // recheck before adding to list
                buffer[nbuffered++] = i;
                setTabAt(nextTab, i, rev);     // install place-holders
                setTabAt(nextTab, i + n, rev);
            }

            if (bin > 0)
                i = --bin;
            else if (buffer != null && nbuffered > 0) {
                bin = -1;
                i = buffer[bufferIndex = --nbuffered];
            }
            else
                return nextTab;
        }
    }

    /**
     * Split a normal bin with list headed by e into lo and hi parts;
     * install in given table
     */
    private static void splitBin(Node[] nextTab, int i, Node e) {
        int bit = nextTab.length >>> 1; // bit to split on
        int runBit = e.hash & bit;
        Node lastRun = e, lo = null, hi = null;
        for (Node p = e.next; p != null; p = p.next) {
            int b = p.hash & bit;
            if (b != runBit) {
                runBit = b;
                lastRun = p;
            }
        }
        if (runBit == 0)
            lo = lastRun;
        else
            hi = lastRun;
        for (Node p = e; p != lastRun; p = p.next) {
            int ph = p.hash & HASH_BITS;
            Object pk = p.key, pv = p.val;
            if ((ph & bit) == 0)
                lo = new Node(ph, pk, pv, lo);
            else
                hi = new Node(ph, pk, pv, hi);
        }
        setTabAt(nextTab, i, lo);
        setTabAt(nextTab, i + bit, hi);
    }

    /**
     * Split a tree bin into lo and hi parts; install in given table
     */
    private static void splitTreeBin(Node[] nextTab, int i, TreeBin t) {
        int bit = nextTab.length >>> 1;
        TreeBin lt = new TreeBin();
        TreeBin ht = new TreeBin();
        int lc = 0, hc = 0;
        for (Node e = t.first; e != null; e = e.next) {
            int h = e.hash & HASH_BITS;
            Object k = e.key, v = e.val;
            if ((h & bit) == 0) {
                ++lc;
                lt.putTreeNode(h, k, v);
            }
            else {
                ++hc;
                ht.putTreeNode(h, k, v);
            }
        }
        Node ln, hn; // throw away trees if too small
        if (lc <= (TREE_THRESHOLD >>> 1)) {
            ln = null;
            for (Node p = lt.first; p != null; p = p.next)
                ln = new Node(p.hash, p.key, p.val, ln);
        }
        else
            ln = new Node(MOVED, lt, null, null);
        setTabAt(nextTab, i, ln);
        if (hc <= (TREE_THRESHOLD >>> 1)) {
            hn = null;
            for (Node p = ht.first; p != null; p = p.next)
                hn = new Node(p.hash, p.key, p.val, hn);
        }
        else
            hn = new Node(MOVED, ht, null, null);
        setTabAt(nextTab, i + bit, hn);
    }

    /**
     * Implementation for clear. Steps through each bin, removing all
     * nodes.
     */
    private final void internalClear() {
        long delta = 0L; // negative number of deletions
        int i = 0;
        Node[] tab = table;
        while (tab != null && i < tab.length) {
            int fh; Object fk;
            Node f = tabAt(tab, i);
            if (f == null)
                ++i;
            else if ((fh = f.hash) == MOVED) {
                if ((fk = f.key) instanceof TreeBin) {
                    TreeBin t = (TreeBin)fk;
                    t.acquire(0);
                    try {
                        if (tabAt(tab, i) == f) {
                            for (Node p = t.first; p != null; p = p.next) {
                                p.val = null;
                                --delta;
                            }
                            t.first = null;
                            t.root = null;
                            ++i;
                        }
                    } finally {
                        t.release(0);
                    }
                }
                else
                    tab = (Node[])fk;
            }
            else if ((fh & LOCKED) != 0) {
                counter.add(delta); // opportunistically update count
                delta = 0L;
                f.tryAwaitLock(tab, i);
            }
            else if (f.casHash(fh, fh | LOCKED)) {
                try {
                    if (tabAt(tab, i) == f) {
                        for (Node e = f; e != null; e = e.next) {
                            e.val = null;
                            --delta;
                        }
                        setTabAt(tab, i, null);
                        ++i;
                    }
                } finally {
                    if (!f.casHash(fh | LOCKED, fh)) {
                        f.hash = fh;
                        synchronized (f) { f.notifyAll(); };
                    }
                }
            }
        }
        if (delta != 0)
            counter.add(delta);
    }

    /* ----------------Table Traversal -------------- */

    /**
     * Encapsulates traversal for methods such as containsValue; also
     * serves as a base class for other iterators.
     *
     * At each step, the iterator snapshots the key ("nextKey") and
     * value ("nextVal") of a valid node (i.e., one that, at point of
     * snapshot, has a non-null user value). Because val fields can
     * change (including to null, indicating deletion), field nextVal
     * might not be accurate at point of use, but still maintains the
     * weak consistency property of holding a value that was once
     * valid.
     *
     * Internal traversals directly access these fields, as in:
     * {@code while (it.next != null) { process(it.nextKey); it.advance(); }}
     *
     * Exported iterators (subclasses of ViewIterator) extract key,
     * value, or key-value pairs as return values of Iterator.next(),
     * and encapsulate the it.next check as hasNext();
     *
     * The iterator visits once each still-valid node that was
     * reachable upon iterator construction. It might miss some that
     * were added to a bin after the bin was visited, which is OK wrt
     * consistency guarantees. Maintaining this property in the face
     * of possible ongoing resizes requires a fair amount of
     * bookkeeping state that is difficult to optimize away amidst
     * volatile accesses.  Even so, traversal maintains reasonable
     * throughput.
     *
     * Normally, iteration proceeds bin-by-bin traversing lists.
     * However, if the table has been resized, then all future steps
     * must traverse both the bin at the current index as well as at
     * (index + baseSize); and so on for further resizings. To
     * paranoically cope with potential sharing by users of iterators
     * across threads, iteration terminates if a bounds checks fails
     * for a table read.
     *
     * The range-based constructor enables creation of parallel
     * range-splitting traversals. (Not yet implemented.)
     */
    static class InternalIterator {
        Node next;           // the next entry to use
        Node last;           // the last entry used
        Object nextKey;      // cached key field of next
        Object nextVal;      // cached val field of next
        Node[] tab;          // current table; updated if resized
        int index;           // index of bin to use next
        int baseIndex;       // current index of initial table
        final int baseLimit; // index bound for initial table
        final int baseSize;  // initial table size

        /** Creates iterator for all entries in the table. */
        InternalIterator(Node[] tab) {
            this.tab = tab;
            baseLimit = baseSize = (tab == null) ? 0 : tab.length;
            index = baseIndex = 0;
            next = null;
            advance();
        }

        /** Creates iterator for the given range of the table */
        InternalIterator(Node[] tab, int lo, int hi) {
            this.tab = tab;
            baseSize = (tab == null) ? 0 : tab.length;
            baseLimit = (hi <= baseSize) ? hi : baseSize;
            index = baseIndex = (lo >= 0) ? lo : 0;
            next = null;
            advance();
        }

        /** Advances next. See above for explanation. */
        final void advance() {
            Node e = last = next;
            outer: do {
                if (e != null)                  // advance past used/skipped node
                    e = e.next;
                while (e == null) {             // get to next non-null bin
                    Node[] t; int b, i, n; Object ek; // checks must use locals
                    if ((b = baseIndex) >= baseLimit || (i = index) < 0 ||
                        (t = tab) == null || i >= (n = t.length))
                        break outer;
                    else if ((e = tabAt(t, i)) != null && e.hash == MOVED) {
                        if ((ek = e.key) instanceof TreeBin)
                            e = ((TreeBin)ek).first;
                        else {
                            tab = (Node[])ek;
                            continue;           // restarts due to null val
                        }
                    }                           // visit upper slots if present
                    index = (i += baseSize) < n ? i : (baseIndex = b + 1);
                }
                nextKey = e.key;
            } while ((nextVal = e.val) == null);// skip deleted or special nodes
            next = e;
        }
    }

    /* ---------------- Public operations -------------- */

    /**
     * Creates a new, empty map with the default initial table size (16),
     */
    public ConcurrentHashMapV8() {
        this.counter = new LongAdder();
    }

    /**
     * Creates a new, empty map with an initial table size
     * accommodating the specified number of elements without the need
     * to dynamically resize.
     *
     * @param initialCapacity The implementation performs internal
     * sizing to accommodate this many elements.
     * @throws IllegalArgumentException if the initial capacity of
     * elements is negative
     */
    public ConcurrentHashMapV8(int initialCapacity) {
        if (initialCapacity < 0)
            throw new IllegalArgumentException();
        int cap = ((initialCapacity >= (MAXIMUM_CAPACITY >>> 1)) ?
                   MAXIMUM_CAPACITY :
                   tableSizeFor(initialCapacity + (initialCapacity >>> 1) + 1));
        this.counter = new LongAdder();
        this.sizeCtl = cap;
    }

    /**
     * Creates a new map with the same mappings as the given map.
     *
     * @param m the map
     */
    public ConcurrentHashMapV8(Map<? extends K, ? extends V> m) {
        this.counter = new LongAdder();
        this.sizeCtl = DEFAULT_CAPACITY;
        internalPutAll(m);
    }

    /**
     * Creates a new, empty map with an initial table size based on
     * the given number of elements ({@code initialCapacity}) and
     * initial table density ({@code loadFactor}).
     *
     * @param initialCapacity the initial capacity. The implementation
     * performs internal sizing to accommodate this many elements,
     * given the specified load factor.
     * @param loadFactor the load factor (table density) for
     * establishing the initial table size
     * @throws IllegalArgumentException if the initial capacity of
     * elements is negative or the load factor is nonpositive
     *
     * @since 1.6
     */
    public ConcurrentHashMapV8(int initialCapacity, float loadFactor) {
        this(initialCapacity, loadFactor, 1);
    }

    /**
     * Creates a new, empty map with an initial table size based on
     * the given number of elements ({@code initialCapacity}), table
     * density ({@code loadFactor}), and number of concurrently
     * updating threads ({@code concurrencyLevel}).
     *
     * @param initialCapacity the initial capacity. The implementation
     * performs internal sizing to accommodate this many elements,
     * given the specified load factor.
     * @param loadFactor the load factor (table density) for
     * establishing the initial table size
     * @param concurrencyLevel the estimated number of concurrently
     * updating threads. The implementation may use this value as
     * a sizing hint.
     * @throws IllegalArgumentException if the initial capacity is
     * negative or the load factor or concurrencyLevel are
     * nonpositive
     */
    public ConcurrentHashMapV8(int initialCapacity,
                               float loadFactor, int concurrencyLevel) {
        if (!(loadFactor > 0.0f) || initialCapacity < 0 || concurrencyLevel <= 0)
            throw new IllegalArgumentException();
        if (initialCapacity < concurrencyLevel)   // Use at least as many bins
            initialCapacity = concurrencyLevel;   // as estimated threads
        long size = (long)(1.0 + (long)initialCapacity / loadFactor);
        int cap = ((size >= (long)MAXIMUM_CAPACITY) ?
                   MAXIMUM_CAPACITY: tableSizeFor((int)size));
        this.counter = new LongAdder();
        this.sizeCtl = cap;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isEmpty() {
        return counter.sum() <= 0L; // ignore transient negative values
    }

    /**
     * {@inheritDoc}
     */
    public int size() {
        long n = counter.sum();
        return ((n < 0L) ? 0 :
                (n > (long)Integer.MAX_VALUE) ? Integer.MAX_VALUE :
                (int)n);
    }

    final long longSize() { // accurate version of size needed for views
        long n = counter.sum();
        return (n < 0L) ? 0L : n;
    }

    /**
     * Returns the value to which the specified key is mapped,
     * or {@code null} if this map contains no mapping for the key.
     *
     * <p>More formally, if this map contains a mapping from a key
     * {@code k} to a value {@code v} such that {@code key.equals(k)},
     * then this method returns {@code v}; otherwise it returns
     * {@code null}.  (There can be at most one such mapping.)
     *
     * @throws NullPointerException if the specified key is null
     */
    @SuppressWarnings("unchecked")
    public V get(Object key) {
        if (key == null)
            throw new NullPointerException();
        return (V)internalGet(key);
    }

    /**
     * Tests if the specified object is a key in this table.
     *
     * @param  key   possible key
     * @return {@code true} if and only if the specified object
     *         is a key in this table, as determined by the
     *         {@code equals} method; {@code false} otherwise
     * @throws NullPointerException if the specified key is null
     */
    public boolean containsKey(Object key) {
        if (key == null)
            throw new NullPointerException();
        return internalGet(key) != null;
    }

    /**
     * Returns {@code true} if this map maps one or more keys to the
     * specified value. Note: This method may require a full traversal
     * of the map, and is much slower than method {@code containsKey}.
     *
     * @param value value whose presence in this map is to be tested
     * @return {@code true} if this map maps one or more keys to the
     *         specified value
     * @throws NullPointerException if the specified value is null
     */
    public boolean containsValue(Object value) {
        if (value == null)
            throw new NullPointerException();
        Object v;
        InternalIterator it = new InternalIterator(table);
        while (it.next != null) {
            if ((v = it.nextVal) == value || value.equals(v))
                return true;
            it.advance();
        }
        return false;
    }

    /**
     * Legacy method testing if some key maps into the specified value
     * in this table.  This method is identical in functionality to
     * {@link #containsValue}, and exists solely to ensure
     * full compatibility with class {@link java.util.Hashtable},
     * which supported this method prior to introduction of the
     * Java Collections framework.
     *
     * @param  value a value to search for
     * @return {@code true} if and only if some key maps to the
     *         {@code value} argument in this table as
     *         determined by the {@code equals} method;
     *         {@code false} otherwise
     * @throws NullPointerException if the specified value is null
     */
    public boolean contains(Object value) {
        return containsValue(value);
    }

    /**
     * Maps the specified key to the specified value in this table.
     * Neither the key nor the value can be null.
     *
     * <p> The value can be retrieved by calling the {@code get} method
     * with a key that is equal to the original key.
     *
     * @param key key with which the specified value is to be associated
     * @param value value to be associated with the specified key
     * @return the previous value associated with {@code key}, or
     *         {@code null} if there was no mapping for {@code key}
     * @throws NullPointerException if the specified key or value is null
     */
    @SuppressWarnings("unchecked")
    public V put(K key, V value) {
        if (key == null || value == null)
            throw new NullPointerException();
        return (V)internalPut(key, value);
    }

    /**
     * {@inheritDoc}
     *
     * @return the previous value associated with the specified key,
     *         or {@code null} if there was no mapping for the key
     * @throws NullPointerException if the specified key or value is null
     */
    @SuppressWarnings("unchecked")
    public V putIfAbsent(K key, V value) {
        if (key == null || value == null)
            throw new NullPointerException();
        return (V)internalPutIfAbsent(key, value);
    }

    /**
     * Copies all of the mappings from the specified map to this one.
     * These mappings replace any mappings that this map had for any of the
     * keys currently in the specified map.
     *
     * @param m mappings to be stored in this map
     */
    public void putAll(Map<? extends K, ? extends V> m) {
        internalPutAll(m);
    }

    /**
     * If the specified key is not already associated with a value,
     * computes its value using the given mappingFunction and
     * enters it into the map.  This is equivalent to
     * <pre> {@code
     * if (map.containsKey(key))
     *   return map.get(key);
     * value = mappingFunction.map(key);
     * map.put(key, value);
     * return value;}</pre>
     *
     * except that the action is performed atomically.  If the
     * function returns {@code null} (in which case a {@code
     * NullPointerException} is thrown), or the function itself throws
     * an (unchecked) exception, the exception is rethrown to its
     * caller, and no mapping is recorded.  Some attempted update
     * operations on this map by other threads may be blocked while
     * computation is in progress, so the computation should be short
     * and simple, and must not attempt to update any other mappings
     * of this Map. The most appropriate usage is to construct a new
     * object serving as an initial mapped value, or memoized result,
     * as in:
     *
     *  <pre> {@code
     * map.computeIfAbsent(key, new MappingFunction<K, V>() {
     *   public V map(K k) { return new Value(f(k)); }});}</pre>
     *
     * @param key key with which the specified value is to be associated
     * @param mappingFunction the function to compute a value
     * @return the current (existing or computed) value associated with
     *         the specified key.
     * @throws NullPointerException if the specified key, mappingFunction,
     *         or computed value is null
     * @throws IllegalStateException if the computation detectably
     *         attempts a recursive update to this map that would
     *         otherwise never complete
     * @throws RuntimeException or Error if the mappingFunction does so,
     *         in which case the mapping is left unestablished
     */
    @SuppressWarnings("unchecked")
    public V computeIfAbsent(K key, MappingFunction<? super K, ? extends V> mappingFunction) {
        if (key == null || mappingFunction == null)
            throw new NullPointerException();
        return (V)internalComputeIfAbsent(key, mappingFunction);
    }

    /**
     * Computes and enters a new mapping value given a key and
     * its current mapped value (or {@code null} if there is no current
     * mapping). This is equivalent to
     *  <pre> {@code
     *  map.put(key, remappingFunction.remap(key, map.get(key));
     * }</pre>
     *
     * except that the action is performed atomically.  If the
     * function returns {@code null} (in which case a {@code
     * NullPointerException} is thrown), or the function itself throws
     * an (unchecked) exception, the exception is rethrown to its
     * caller, and current mapping is left unchanged.  Some attempted
     * update operations on this map by other threads may be blocked
     * while computation is in progress, so the computation should be
     * short and simple, and must not attempt to update any other
     * mappings of this Map. For example, to either create or
     * append new messages to a value mapping:
     *
     * <pre> {@code
     * Map<Key, String> map = ...;
     * final String msg = ...;
     * map.compute(key, new RemappingFunction<Key, String>() {
     *   public String remap(Key k, String v) {
     *    return (v == null) ? msg : v + msg;});}}</pre>
     *
     * @param key key with which the specified value is to be associated
     * @param remappingFunction the function to compute a value
     * @return the new value associated with
     *         the specified key.
     * @throws NullPointerException if the specified key or remappingFunction
     *         or computed value is null
     * @throws IllegalStateException if the computation detectably
     *         attempts a recursive update to this map that would
     *         otherwise never complete
     * @throws RuntimeException or Error if the remappingFunction does so,
     *         in which case the mapping is unchanged
     */
    @SuppressWarnings("unchecked")
    public V compute(K key, RemappingFunction<? super K, V> remappingFunction) {
        if (key == null || remappingFunction == null)
            throw new NullPointerException();
        return (V)internalCompute(key, remappingFunction);
    }

    /**
     * Removes the key (and its corresponding value) from this map.
     * This method does nothing if the key is not in the map.
     *
     * @param  key the key that needs to be removed
     * @return the previous value associated with {@code key}, or
     *         {@code null} if there was no mapping for {@code key}
     * @throws NullPointerException if the specified key is null
     */
    @SuppressWarnings("unchecked")
    public V remove(Object key) {
        if (key == null)
            throw new NullPointerException();
        return (V)internalReplace(key, null, null);
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException if the specified key is null
     */
    public boolean remove(Object key, Object value) {
        if (key == null)
            throw new NullPointerException();
        if (value == null)
            return false;
        return internalReplace(key, null, value) != null;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException if any of the arguments are null
     */
    public boolean replace(K key, V oldValue, V newValue) {
        if (key == null || oldValue == null || newValue == null)
            throw new NullPointerException();
        return internalReplace(key, newValue, oldValue) != null;
    }

    /**
     * {@inheritDoc}
     *
     * @return the previous value associated with the specified key,
     *         or {@code null} if there was no mapping for the key
     * @throws NullPointerException if the specified key or value is null
     */
    @SuppressWarnings("unchecked")
    public V replace(K key, V value) {
        if (key == null || value == null)
            throw new NullPointerException();
        return (V)internalReplace(key, value, null);
    }

    /**
     * Removes all of the mappings from this map.
     */
    public void clear() {
        internalClear();
    }

    /**
     * Returns a {@link Set} view of the keys contained in this map.
     * The set is backed by the map, so changes to the map are
     * reflected in the set, and vice-versa.  The set supports element
     * removal, which removes the corresponding mapping from this map,
     * via the {@code Iterator.remove}, {@code Set.remove},
     * {@code removeAll}, {@code retainAll}, and {@code clear}
     * operations.  It does not support the {@code add} or
     * {@code addAll} operations.
     *
     * <p>The view's {@code iterator} is a "weakly consistent" iterator
     * that will never throw {@link ConcurrentModificationException},
     * and guarantees to traverse elements as they existed upon
     * construction of the iterator, and may (but is not guaranteed to)
     * reflect any modifications subsequent to construction.
     */
    public Set<K> keySet() {
        KeySet<K,V> ks = keySet;
        return (ks != null) ? ks : (keySet = new KeySet<K,V>(this));
    }

    /**
     * Returns a {@link Collection} view of the values contained in this map.
     * The collection is backed by the map, so changes to the map are
     * reflected in the collection, and vice-versa.  The collection
     * supports element removal, which removes the corresponding
     * mapping from this map, via the {@code Iterator.remove},
     * {@code Collection.remove}, {@code removeAll},
     * {@code retainAll}, and {@code clear} operations.  It does not
     * support the {@code add} or {@code addAll} operations.
     *
     * <p>The view's {@code iterator} is a "weakly consistent" iterator
     * that will never throw {@link ConcurrentModificationException},
     * and guarantees to traverse elements as they existed upon
     * construction of the iterator, and may (but is not guaranteed to)
     * reflect any modifications subsequent to construction.
     */
    public Collection<V> values() {
        Values<K,V> vs = values;
        return (vs != null) ? vs : (values = new Values<K,V>(this));
    }

    /**
     * Returns a {@link Set} view of the mappings contained in this map.
     * The set is backed by the map, so changes to the map are
     * reflected in the set, and vice-versa.  The set supports element
     * removal, which removes the corresponding mapping from the map,
     * via the {@code Iterator.remove}, {@code Set.remove},
     * {@code removeAll}, {@code retainAll}, and {@code clear}
     * operations.  It does not support the {@code add} or
     * {@code addAll} operations.
     *
     * <p>The view's {@code iterator} is a "weakly consistent" iterator
     * that will never throw {@link ConcurrentModificationException},
     * and guarantees to traverse elements as they existed upon
     * construction of the iterator, and may (but is not guaranteed to)
     * reflect any modifications subsequent to construction.
     */
    public Set<Map.Entry<K,V>> entrySet() {
        EntrySet<K,V> es = entrySet;
        return (es != null) ? es : (entrySet = new EntrySet<K,V>(this));
    }

    /**
     * Returns an enumeration of the keys in this table.
     *
     * @return an enumeration of the keys in this table
     * @see #keySet()
     */
    public Enumeration<K> keys() {
        return new KeyIterator<K,V>(this);
    }

    /**
     * Returns an enumeration of the values in this table.
     *
     * @return an enumeration of the values in this table
     * @see #values()
     */
    public Enumeration<V> elements() {
        return new ValueIterator<K,V>(this);
    }

    /**
     * Returns the hash code value for this {@link Map}, i.e.,
     * the sum of, for each key-value pair in the map,
     * {@code key.hashCode() ^ value.hashCode()}.
     *
     * @return the hash code value for this map
     */
    public int hashCode() {
        int h = 0;
        InternalIterator it = new InternalIterator(table);
        while (it.next != null) {
            h += it.nextKey.hashCode() ^ it.nextVal.hashCode();
            it.advance();
        }
        return h;
    }

    /**
     * Returns a string representation of this map.  The string
     * representation consists of a list of key-value mappings (in no
     * particular order) enclosed in braces ("{@code {}}").  Adjacent
     * mappings are separated by the characters {@code ", "} (comma
     * and space).  Each key-value mapping is rendered as the key
     * followed by an equals sign ("{@code =}") followed by the
     * associated value.
     *
     * @return a string representation of this map
     */
    public String toString() {
        InternalIterator it = new InternalIterator(table);
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        if (it.next != null) {
            for (;;) {
                Object k = it.nextKey, v = it.nextVal;
                sb.append(k == this ? "(this Map)" : k);
                sb.append('=');
                sb.append(v == this ? "(this Map)" : v);
                it.advance();
                if (it.next == null)
                    break;
                sb.append(',').append(' ');
            }
        }
        return sb.append('}').toString();
    }

    /**
     * Compares the specified object with this map for equality.
     * Returns {@code true} if the given object is a map with the same
     * mappings as this map.  This operation may return misleading
     * results if either map is concurrently modified during execution
     * of this method.
     *
     * @param o object to be compared for equality with this map
     * @return {@code true} if the specified object is equal to this map
     */
    public boolean equals(Object o) {
        if (o != this) {
            if (!(o instanceof Map))
                return false;
            Map<?,?> m = (Map<?,?>) o;
            InternalIterator it = new InternalIterator(table);
            while (it.next != null) {
                Object val = it.nextVal;
                Object v = m.get(it.nextKey);
                if (v == null || (v != val && !v.equals(val)))
                    return false;
                it.advance();
            }
            for (Map.Entry<?,?> e : m.entrySet()) {
                Object mk, mv, v;
                if ((mk = e.getKey()) == null ||
                    (mv = e.getValue()) == null ||
                    (v = internalGet(mk)) == null ||
                    (mv != v && !mv.equals(v)))
                    return false;
            }
        }
        return true;
    }

    /* ----------------Iterators -------------- */

    /**
     * Base class for key, value, and entry iterators.  Adds a map
     * reference to InternalIterator to support Iterator.remove.
     */
    static abstract class ViewIterator<K,V> extends InternalIterator {
        final ConcurrentHashMapV8<K, V> map;
        ViewIterator(ConcurrentHashMapV8<K, V> map) {
            super(map.table);
            this.map = map;
        }

        public final void remove() {
            if (last == null)
                throw new IllegalStateException();
            map.remove(last.key);
            last = null;
        }

        public final boolean hasNext()         { return next != null; }
        public final boolean hasMoreElements() { return next != null; }
    }

    static final class KeyIterator<K,V> extends ViewIterator<K,V>
        implements Iterator<K>, Enumeration<K> {
        KeyIterator(ConcurrentHashMapV8<K, V> map) { super(map); }

        @SuppressWarnings("unchecked")
        public final K next() {
            if (next == null)
                throw new NoSuchElementException();
            Object k = nextKey;
            advance();
            return (K)k;
        }

        public final K nextElement() { return next(); }
    }

    static final class ValueIterator<K,V> extends ViewIterator<K,V>
        implements Iterator<V>, Enumeration<V> {
        ValueIterator(ConcurrentHashMapV8<K, V> map) { super(map); }

        @SuppressWarnings("unchecked")
        public final V next() {
            if (next == null)
                throw new NoSuchElementException();
            Object v = nextVal;
            advance();
            return (V)v;
        }

        public final V nextElement() { return next(); }
    }

    static final class EntryIterator<K,V> extends ViewIterator<K,V>
        implements Iterator<Map.Entry<K,V>> {
        EntryIterator(ConcurrentHashMapV8<K, V> map) { super(map); }

        @SuppressWarnings("unchecked")
        public final Map.Entry<K,V> next() {
            if (next == null)
                throw new NoSuchElementException();
            Object k = nextKey;
            Object v = nextVal;
            advance();
            return new WriteThroughEntry<K,V>((K)k, (V)v, map);
        }
    }

    static final class SnapshotEntryIterator<K,V> extends ViewIterator<K,V>
        implements Iterator<Map.Entry<K,V>> {
        SnapshotEntryIterator(ConcurrentHashMapV8<K, V> map) { super(map); }

        @SuppressWarnings("unchecked")
        public final Map.Entry<K,V> next() {
            if (next == null)
                throw new NoSuchElementException();
            Object k = nextKey;
            Object v = nextVal;
            advance();
            return new SnapshotEntry<K,V>((K)k, (V)v);
        }
    }

    /**
     * Base of writeThrough and Snapshot entry classes
     */
    static abstract class MapEntry<K,V> implements Map.Entry<K, V> {
        final K key; // non-null
        V val;       // non-null
        MapEntry(K key, V val)        { this.key = key; this.val = val; }
        public final K getKey()       { return key; }
        public final V getValue()     { return val; }
        public final int hashCode()   { return key.hashCode() ^ val.hashCode(); }
        public final String toString(){ return key + "=" + val; }

        public final boolean equals(Object o) {
            Object k, v; Map.Entry<?,?> e;
            return ((o instanceof Map.Entry) &&
                    (k = (e = (Map.Entry<?,?>)o).getKey()) != null &&
                    (v = e.getValue()) != null &&
                    (k == key || k.equals(key)) &&
                    (v == val || v.equals(val)));
        }

        public abstract V setValue(V value);
    }

    /**
     * Entry used by EntryIterator.next(), that relays setValue
     * changes to the underlying map.
     */
    static final class WriteThroughEntry<K,V> extends MapEntry<K,V>
        implements Map.Entry<K, V> {
        final ConcurrentHashMapV8<K, V> map;
        WriteThroughEntry(K key, V val, ConcurrentHashMapV8<K, V> map) {
            super(key, val);
            this.map = map;
        }

        /**
         * Sets our entry's value and writes through to the map. The
         * value to return is somewhat arbitrary here. Since a
         * WriteThroughEntry does not necessarily track asynchronous
         * changes, the most recent "previous" value could be
         * different from what we return (or could even have been
         * removed in which case the put will re-establish). We do not
         * and cannot guarantee more.
         */
        public final V setValue(V value) {
            if (value == null) throw new NullPointerException();
            V v = val;
            val = value;
            map.put(key, value);
            return v;
        }
    }

    /**
     * Internal version of entry, that doesn't write though changes
     */
    static final class SnapshotEntry<K,V> extends MapEntry<K,V>
        implements Map.Entry<K, V> {
        SnapshotEntry(K key, V val) { super(key, val); }
        public final V setValue(V value) { // only locally update
            if (value == null) throw new NullPointerException();
            V v = val;
            val = value;
            return v;
        }
    }

    /* ----------------Views -------------- */

    /**
     * Base class for views. This is done mainly to allow adding
     * customized parallel traversals (not yet implemented.)
     */
    static abstract class MapView<K, V> {
        final ConcurrentHashMapV8<K, V> map;
        MapView(ConcurrentHashMapV8<K, V> map)  { this.map = map; }
        public final int size()                 { return map.size(); }
        public final boolean isEmpty()          { return map.isEmpty(); }
        public final void clear()               { map.clear(); }

        // implementations below rely on concrete classes supplying these
        abstract Iterator<?> iter();
        abstract public boolean contains(Object o);
        abstract public boolean remove(Object o);

        private static final String oomeMsg = "Required array size too large";

        public final Object[] toArray() {
            long sz = map.longSize();
            if (sz > (long)(MAX_ARRAY_SIZE))
                throw new OutOfMemoryError(oomeMsg);
            int n = (int)sz;
            Object[] r = new Object[n];
            int i = 0;
            Iterator<?> it = iter();
            while (it.hasNext()) {
                if (i == n) {
                    if (n >= MAX_ARRAY_SIZE)
                        throw new OutOfMemoryError(oomeMsg);
                    if (n >= MAX_ARRAY_SIZE - (MAX_ARRAY_SIZE >>> 1) - 1)
                        n = MAX_ARRAY_SIZE;
                    else
                        n += (n >>> 1) + 1;
                    r = Arrays.copyOf(r, n);
                }
                r[i++] = it.next();
            }
            return (i == n) ? r : Arrays.copyOf(r, i);
        }

        @SuppressWarnings("unchecked")
        public final <T> T[] toArray(T[] a) {
            long sz = map.longSize();
            if (sz > (long)(MAX_ARRAY_SIZE))
                throw new OutOfMemoryError(oomeMsg);
            int m = (int)sz;
            T[] r = (a.length >= m) ? a :
                (T[])java.lang.reflect.Array
                .newInstance(a.getClass().getComponentType(), m);
            int n = r.length;
            int i = 0;
            Iterator<?> it = iter();
            while (it.hasNext()) {
                if (i == n) {
                    if (n >= MAX_ARRAY_SIZE)
                        throw new OutOfMemoryError(oomeMsg);
                    if (n >= MAX_ARRAY_SIZE - (MAX_ARRAY_SIZE >>> 1) - 1)
                        n = MAX_ARRAY_SIZE;
                    else
                        n += (n >>> 1) + 1;
                    r = Arrays.copyOf(r, n);
                }
                r[i++] = (T)it.next();
            }
            if (a == r && i < n) {
                r[i] = null; // null-terminate
                return r;
            }
            return (i == n) ? r : Arrays.copyOf(r, i);
        }

        public final int hashCode() {
            int h = 0;
            for (Iterator<?> it = iter(); it.hasNext();)
                h += it.next().hashCode();
            return h;
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            Iterator<?> it = iter();
            if (it.hasNext()) {
                for (;;) {
                    Object e = it.next();
                    sb.append(e == this ? "(this Collection)" : e);
                    if (!it.hasNext())
                        break;
                    sb.append(',').append(' ');
                }
            }
            return sb.append(']').toString();
        }

        public final boolean containsAll(Collection<?> c) {
            if (c != this) {
                for (Iterator<?> it = c.iterator(); it.hasNext();) {
                    Object e = it.next();
                    if (e == null || !contains(e))
                        return false;
                }
            }
            return true;
        }

        public final boolean removeAll(Collection<?> c) {
            boolean modified = false;
            for (Iterator<?> it = iter(); it.hasNext();) {
                if (c.contains(it.next())) {
                    it.remove();
                    modified = true;
                }
            }
            return modified;
        }

        public final boolean retainAll(Collection<?> c) {
            boolean modified = false;
            for (Iterator<?> it = iter(); it.hasNext();) {
                if (!c.contains(it.next())) {
                    it.remove();
                    modified = true;
                }
            }
            return modified;
        }

    }

    static final class KeySet<K,V> extends MapView<K,V> implements Set<K> {
        KeySet(ConcurrentHashMapV8<K, V> map)   { super(map); }
        public final boolean contains(Object o) { return map.containsKey(o); }
        public final boolean remove(Object o)   { return map.remove(o) != null; }

        public final Iterator<K> iterator() {
            return new KeyIterator<K,V>(map);
        }
        final Iterator<?> iter() {
            return new KeyIterator<K,V>(map);
        }
        public final boolean add(K e) {
            throw new UnsupportedOperationException();
        }
        public final boolean addAll(Collection<? extends K> c) {
            throw new UnsupportedOperationException();
        }
        public boolean equals(Object o) {
            Set<?> c;
            return ((o instanceof Set) &&
                    ((c = (Set<?>)o) == this ||
                     (containsAll(c) && c.containsAll(this))));
        }
    }

    static final class Values<K,V> extends MapView<K,V>
        implements Collection<V> {
        Values(ConcurrentHashMapV8<K, V> map)   { super(map); }
        public final boolean contains(Object o) { return map.containsValue(o); }

        public final boolean remove(Object o) {
            if (o != null) {
                Iterator<V> it = new ValueIterator<K,V>(map);
                while (it.hasNext()) {
                    if (o.equals(it.next())) {
                        it.remove();
                        return true;
                    }
                }
            }
            return false;
        }
        public final Iterator<V> iterator() {
            return new ValueIterator<K,V>(map);
        }
        final Iterator<?> iter() {
            return new ValueIterator<K,V>(map);
        }
        public final boolean add(V e) {
            throw new UnsupportedOperationException();
        }
        public final boolean addAll(Collection<? extends V> c) {
            throw new UnsupportedOperationException();
        }
    }

    static final class EntrySet<K,V> extends MapView<K,V>
        implements Set<Map.Entry<K,V>> {
        EntrySet(ConcurrentHashMapV8<K, V> map) { super(map); }

        public final boolean contains(Object o) {
            Object k, v, r; Map.Entry<?,?> e;
            return ((o instanceof Map.Entry) &&
                    (k = (e = (Map.Entry<?,?>)o).getKey()) != null &&
                    (r = map.get(k)) != null &&
                    (v = e.getValue()) != null &&
                    (v == r || v.equals(r)));
        }

        public final boolean remove(Object o) {
            Object k, v; Map.Entry<?,?> e;
            return ((o instanceof Map.Entry) &&
                    (k = (e = (Map.Entry<?,?>)o).getKey()) != null &&
                    (v = e.getValue()) != null &&
                    map.remove(k, v));
        }

        public final Iterator<Map.Entry<K,V>> iterator() {
            return new EntryIterator<K,V>(map);
        }
        final Iterator<?> iter() {
            return new SnapshotEntryIterator<K,V>(map);
        }
        public final boolean add(Entry<K,V> e) {
            throw new UnsupportedOperationException();
        }
        public final boolean addAll(Collection<? extends Entry<K,V>> c) {
            throw new UnsupportedOperationException();
        }
        public boolean equals(Object o) {
            Set<?> c;
            return ((o instanceof Set) &&
                    ((c = (Set<?>)o) == this ||
                     (containsAll(c) && c.containsAll(this))));
        }
    }

    /* ---------------- Serialization Support -------------- */

    /**
     * Stripped-down version of helper class used in previous version,
     * declared for the sake of serialization compatibility
     */
    static class Segment<K,V> implements Serializable {
        private static final long serialVersionUID = 2249069246763182397L;
        final float loadFactor;
        Segment(float lf) { this.loadFactor = lf; }
    }

    /**
     * Saves the state of the {@code ConcurrentHashMapV8} instance to a
     * stream (i.e., serializes it).
     * @param s the stream
     * @serialData
     * the key (Object) and value (Object)
     * for each key-value mapping, followed by a null pair.
     * The key-value mappings are emitted in no particular order.
     */
    @SuppressWarnings("unchecked")
    private void writeObject(java.io.ObjectOutputStream s)
            throws java.io.IOException {
        if (segments == null) { // for serialization compatibility
            segments = (Segment<K,V>[])
                new Segment<?,?>[DEFAULT_CONCURRENCY_LEVEL];
            for (int i = 0; i < segments.length; ++i)
                segments[i] = new Segment<K,V>(LOAD_FACTOR);
        }
        s.defaultWriteObject();
        InternalIterator it = new InternalIterator(table);
        while (it.next != null) {
            s.writeObject(it.nextKey);
            s.writeObject(it.nextVal);
            it.advance();
        }
        s.writeObject(null);
        s.writeObject(null);
        segments = null; // throw away
    }

    /**
     * Reconstitutes the instance from a stream (that is, deserializes it).
     * @param s the stream
     */
    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();
        this.segments = null; // unneeded
        // initialize transient final field
        UNSAFE.putObjectVolatile(this, counterOffset, new LongAdder());

        // Create all nodes, then place in table once size is known
        long size = 0L;
        Node p = null;
        for (;;) {
            K k = (K) s.readObject();
            V v = (V) s.readObject();
            if (k != null && v != null) {
                int h = spread(k.hashCode());
                p = new Node(h, k, v, p);
                ++size;
            }
            else
                break;
        }
        if (p != null) {
            boolean init = false;
            int n;
            if (size >= (long)(MAXIMUM_CAPACITY >>> 1))
                n = MAXIMUM_CAPACITY;
            else {
                int sz = (int)size;
                n = tableSizeFor(sz + (sz >>> 1) + 1);
            }
            int sc = sizeCtl;
            boolean collide = false;
            if (n > sc &&
                UNSAFE.compareAndSwapInt(this, sizeCtlOffset, sc, -1)) {
                try {
                    if (table == null) {
                        init = true;
                        Node[] tab = new Node[n];
                        int mask = n - 1;
                        while (p != null) {
                            int j = p.hash & mask;
                            Node next = p.next;
                            Node q = p.next = tabAt(tab, j);
                            setTabAt(tab, j, p);
                            if (!collide && q != null && q.hash == p.hash)
                                collide = true;
                            p = next;
                        }
                        table = tab;
                        counter.add(size);
                        sc = n - (n >>> 2);
                    }
                } finally {
                    sizeCtl = sc;
                }
                if (collide) { // rescan and convert to TreeBins
                    Node[] tab = table;
                    for (int i = 0; i < tab.length; ++i) {
                        int c = 0;
                        for (Node e = tabAt(tab, i); e != null; e = e.next) {
                            if (++c > TREE_THRESHOLD &&
                                (e.key instanceof Comparable)) {
                                replaceWithTreeBin(tab, i, e.key);
                                break;
                            }
                        }
                    }
                }
            }
            if (!init) { // Can only happen if unsafely published.
                while (p != null) {
                    internalPut(p.key, p.val);
                    p = p.next;
                }
            }

        }
    }

    // Unsafe mechanics
    private static final sun.misc.Unsafe UNSAFE;
    private static final long counterOffset;
    private static final long sizeCtlOffset;
    private static final long ABASE;
    private static final int ASHIFT;

    static {
        int ss;
        try {
            UNSAFE = getUnsafe();
            Class<?> k = ConcurrentHashMapV8.class;
            counterOffset = UNSAFE.objectFieldOffset
                (k.getDeclaredField("counter"));
            sizeCtlOffset = UNSAFE.objectFieldOffset
                (k.getDeclaredField("sizeCtl"));
            Class<?> sc = Node[].class;
            ABASE = UNSAFE.arrayBaseOffset(sc);
            ss = UNSAFE.arrayIndexScale(sc);
        } catch (Exception e) {
            throw new Error(e);
        }
        if ((ss & (ss-1)) != 0)
            throw new Error("data type scale not a power of two");
        ASHIFT = 31 - Integer.numberOfLeadingZeros(ss);
    }

    /**
     * Returns a sun.misc.Unsafe.  Suitable for use in a 3rd party package.
     * Replace with a simple call to Unsafe.getUnsafe when integrating
     * into a jdk.
     *
     * @return a sun.misc.Unsafe
     */
    private static sun.misc.Unsafe getUnsafe() {
        try {
            return sun.misc.Unsafe.getUnsafe();
        } catch (SecurityException se) {
            try {
                return java.security.AccessController.doPrivileged
                    (new java.security
                     .PrivilegedExceptionAction<sun.misc.Unsafe>() {
                        public sun.misc.Unsafe run() throws Exception {
                            java.lang.reflect.Field f = sun.misc
                                .Unsafe.class.getDeclaredField("theUnsafe");
                            f.setAccessible(true);
                            return (sun.misc.Unsafe) f.get(null);
                        }});
            } catch (java.security.PrivilegedActionException e) {
                throw new RuntimeException("Could not initialize intrinsics",
                                           e.getCause());
            }
        }
    }

}
