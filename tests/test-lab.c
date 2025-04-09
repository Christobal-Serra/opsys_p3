#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"

struct avail *get_block_metadata(void *ptr);


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}



/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}

void test_btok_conversion(void) {
  fprintf(stderr, "->Testing btok conversion\n");

  // Basic powers of 2
  TEST_ASSERT_EQUAL_UINT64(0, btok(1));
  TEST_ASSERT_EQUAL_UINT64(1, btok(2));
  TEST_ASSERT_EQUAL_UINT64(2, btok(4));
  TEST_ASSERT_EQUAL_UINT64(3, btok(8));
  TEST_ASSERT_EQUAL_UINT64(10, btok(1024));

  // Not exact powers of 2 (should round up)
  TEST_ASSERT_EQUAL_UINT64(3, btok(5));      // 2^3 = 8
  TEST_ASSERT_EQUAL_UINT64(6, btok(33));     // 2^6 = 64
  TEST_ASSERT_EQUAL_UINT64(6, btok(34));     // 2^6 = 64
  TEST_ASSERT_EQUAL_UINT64(20, btok(1 << 20)); // 1 MiB

  // Edge case: 0 bytes should return 0 (even though it's invalid for malloc)
  TEST_ASSERT_EQUAL_UINT64(0, btok(0));
}

void test_buddy_calc_known_pair(void) {
  fprintf(stderr, "->Testing buddy_calc with known address\n");

  struct buddy_pool pool;
  size_t kval = 4; // 2^4 = 16 byte block size
  size_t size = UINT64_C(1) << kval;

  buddy_init(&pool, size);

  struct avail *block = (struct avail *)pool.base;
  block->kval = kval;

  struct avail *expected_buddy = (struct avail *)((uintptr_t)block ^ (UINT64_C(1) << kval));
  struct avail *actual_buddy = buddy_calc(&pool, block);

  TEST_ASSERT_EQUAL_PTR(expected_buddy, actual_buddy);

  buddy_destroy(&pool);
}

void test_buddy_alloc_free_merge(void) {
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << 10); // 1 KiB pool
  
  void *ptr = buddy_malloc(&pool, 100); // Should allocate from smaller block
  TEST_ASSERT_NOT_NULL(ptr);
  
  buddy_free(&pool, ptr);
  check_buddy_pool_full(&pool); // Pool should be whole again
  
  buddy_destroy(&pool);
}

void test_partial_merge_behavior(void) {
  fprintf(stderr, "->Testing partial free and merge behavior\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << 13; // 8 KiB
  buddy_init(&pool, size);

  // Allocate 4 blocks of 32 bytes (will be rounded up internally)
  void *a = buddy_malloc(&pool, 32);
  void *b = buddy_malloc(&pool, 32);
  void *c = buddy_malloc(&pool, 32);
  void *d = buddy_malloc(&pool, 32);
  fprintf(stderr, "a: %p, b: %p, c: %p, d: %p\n", a, b, c, d);


  // Assert all were allocated
  TEST_ASSERT_NOT_NULL(a);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_NOT_NULL(d);

  // Free b and a — they should merge
  buddy_free(&pool, b);
  buddy_free(&pool, a);

  // Get metadata for c and d and make sure they’re still in use
  struct avail *meta_c = get_block_metadata(c);
  struct avail *meta_d = get_block_metadata(d);

  TEST_ASSERT_NOT_NULL(meta_c);
  TEST_ASSERT_NOT_NULL(meta_d);
  TEST_ASSERT_EQUAL_UINT8(BLOCK_RESERVED, meta_c->tag);
  TEST_ASSERT_EQUAL_UINT8(BLOCK_RESERVED, meta_d->tag);

  // Search for the merged block in the freelist
  int found_merged = 0;
  for (size_t k = 0; k <= pool.kval_m; ++k) {
    struct avail *head = &pool.avail[k];
    for (struct avail *cur = head->next; cur != head; cur = cur->next) {
      if (cur->tag == BLOCK_AVAIL && cur->kval == 7) {
        found_merged = 1;
        break;
      }
    }
    if (found_merged) break;
  }

  TEST_ASSERT_TRUE_MESSAGE(found_merged, "Expected merged a+b block not found in freelist");

  // Cleanup
  buddy_free(&pool, c);
  buddy_free(&pool, d);
  buddy_destroy(&pool);
}

int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_btok_conversion);
  RUN_TEST(test_buddy_calc_known_pair);
  RUN_TEST(test_buddy_alloc_free_merge);
  RUN_TEST(test_partial_merge_behavior);
  return UNITY_END();
}
