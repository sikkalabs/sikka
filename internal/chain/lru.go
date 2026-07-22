//go:build !js

package chain

// lruNode represents a single entry in the doubly-linked list.
type lruNode struct {
	key  string
	val  *Transaction
	prev *lruNode
	next *lruNode
}

// lruCache is a thread-unsafe LRU cache. It is guarded by DAG.mu.
type lruCache struct {
	capacity int
	items    map[string]*lruNode
	head     *lruNode // Most Recently Used
	tail     *lruNode // Least Recently Used
}

func newLRUCache(capacity int) *lruCache {
	if capacity <= 0 {
		capacity = DefaultTxCacheCapacity
	}
	return &lruCache{
		capacity: capacity,
		items:    make(map[string]*lruNode, capacity),
	}
}

func (c *lruCache) Get(key string) (*Transaction, bool) {
	if c == nil || c.capacity <= 0 {
		return nil, false
	}
	node, exists := c.items[key]
	if !exists {
		return nil, false
	}
	c.moveToFront(node)
	return node.val, true
}

func (c *lruCache) Put(key string, val *Transaction) {
	if c == nil || c.capacity <= 0 || val == nil {
		return
	}
	if node, exists := c.items[key]; exists {
		node.val = val
		c.moveToFront(node)
		return
	}

	node := &lruNode{key: key, val: val}
	c.items[key] = node
	c.addToFront(node)

	if len(c.items) > c.capacity {
		c.evictTail()
	}
}

func (c *lruCache) Remove(key string) {
	if c == nil || c.capacity <= 0 {
		return
	}
	if node, exists := c.items[key]; exists {
		c.removeNode(node)
		delete(c.items, key)
	}
}

func (c *lruCache) Len() int {
	if c == nil {
		return 0
	}
	return len(c.items)
}

func (c *lruCache) addToFront(node *lruNode) {
	node.next = c.head
	node.prev = nil
	if c.head != nil {
		c.head.prev = node
	}
	c.head = node
	if c.tail == nil {
		c.tail = node
	}
}

func (c *lruCache) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		c.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		c.tail = node.prev
	}
	node.prev = nil
	node.next = nil
}

func (c *lruCache) moveToFront(node *lruNode) {
	if c.head == node {
		return
	}
	c.removeNode(node)
	c.addToFront(node)
}

func (c *lruCache) evictTail() {
	if c.tail == nil {
		return
	}
	evicted := c.tail
	c.removeNode(evicted)
	delete(c.items, evicted.key)
}
