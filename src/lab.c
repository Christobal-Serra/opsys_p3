/**
 * @file lab.c
 * @brief Implementation of a Buddy System Memory Allocator.
 *
 * Memory allocator based on the buddy system. The allocator ensures efficient memory 
 * usage by dividing memory blocks into 'buddy' blocks.
 */


#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes) {
    size_t k = 0;
    size_t block_size = UINT64_C(1); // C99 macro ensures it's treated as a 64-bit constant
    while (block_size < bytes) {
        block_size <<= 1; // equivalent to multiplying by 2
        k++;
    }
    return k;
}

/**
 * @brief Removes a block from its free list.
 * 
 * @param block Pointer to the block to be removed.
 */
 static void remove_from_freelist(struct avail *block) {
    block->next->prev = block->prev;
    block->prev->next = block->next;
}

/**
 * @brief Inserts a block into the free list.
 * 
 * @param pool Pointer to the buddy pool.
 * @param block Pointer to the block to be inserted.
 * @param kval The size class of the block.
 */
void insert_into_freelist(struct buddy_pool *pool, struct avail *block, size_t kval) {
    block->next = pool->avail[kval].next;
    block->prev = &pool->avail[kval];
    pool->avail[kval].next->prev = block;
    pool->avail[kval].next = block;
}

/**
 * @brief Checks if a block is within the bounds of the buddy pool.
 * 
 * @param pool Pointer to the buddy pool.
 * @param block Pointer to the block to check.
 * @return true if the block is within the pool, false otherwise.
 */
bool block_in_bounds(struct buddy_pool *pool, struct avail *block) {
    uintptr_t addr = (uintptr_t)block;
    uintptr_t base = (uintptr_t)pool->base;
    return addr >= base && addr < base + pool->numbytes;
}

/**
 * @brief Checks if a block is within the bounds of the buddy pool.
 * 
 * @param pool Pointer to the buddy pool.
 * @param buddy Pointer to the block to check.
 * @return true if the block is within the pool, false otherwise.
 */
bool can_merge(struct buddy_pool *pool, struct avail *buddy, size_t kval) {
    return block_in_bounds(pool, buddy) && 
            (buddy->tag == BLOCK_AVAIL) && 
            (buddy->kval == kval);
}

/**
 * @brief Checks if a block is within the bounds of the buddy pool.
 * 
 * @param pool Pointer to the buddy pool.
 * @param block Pointer to the block to check.
 * @return true if the block is within the pool, false otherwise.
 */
struct avail *get_block_metadata(void *ptr) {
    return ((struct avail *)ptr)-1;
}

/**
 * @brief Finds the next kval index with a non-empty free list.
 *
 * @param pool The memory pool.
 * @param start_k The starting kval to search from.
 * @return The kval index with a non-empty list, or pool->kval_m + 1 if none found.
 */
 static size_t find_next_nonempty_kval(struct buddy_pool *pool, size_t start_k) {
    size_t k = start_k;
    while ( (k <= pool->kval_m) && (pool->avail[k].next == &pool->avail[k]) ) {
        k++;
    }
    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    /* Convert the block's address to an offset relative to the base of the pool to ensure that 
    our we are consistent regardless of where the memory was mapped in the virtual address space. */
    uintptr_t offset = (uintptr_t)buddy - (uintptr_t)pool->base;
    /* Calculate the buddy offset by XORing the block's offset with the size of the block. This flips 
    the bit corresponding to buddy->kval, giving us the relative offset of the buddy block. */
    uintptr_t buddy_offset = offset ^ (UINT64_C(1) << buddy->kval);
    /* Add the buddy offset back to the pool's base address to get the actual address of the buddy block. 
    Cast it to the avail struct and return. */
    return (struct avail *)((uintptr_t)pool->base + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (!pool || size == 0) { // Check for NULL pool or size
        return NULL;
    }
    /* Calculate the smallest power-of-two block size needed to fulfill the request. Requested 
    size + the space for the metadata (struct avail). Use btok to return the smallest k such that 
    2^k is large enough to fit everything. */
    size_t kval = btok(size + sizeof(struct avail));
    // Enforce minimum block size
    if (kval < SMALLEST_K) {
        kval = SMALLEST_K;
    }
    /* Search for the smallest available block that can satisfy the request. */
    size_t current_k = find_next_nonempty_kval(pool, kval);
    // No memory big enough found — set error and return NULL.
    if (current_k > pool->kval_m) {
        errno = ENOMEM; // EMONEM is no memory available macro
        return NULL;
    }
    // Remove the memory from free list, so that we can use it.
    struct avail *block = pool->avail[current_k].next;
    remove_from_freelist(block);
    // Split required?
    while (current_k > kval) {
        current_k--; // Decrease the size of the block to split
        block->kval = current_k; // Must set kval first so buddy_calc sees the right value
        struct avail *buddy = buddy_calc(pool, block); // Now buddy_calc uses correct kval
        // Always keep the lower address as the one to continue splitting
        if (buddy < block) {
            struct avail *temp = block;
            block = buddy;
            buddy = temp;
        }
        if (!block_in_bounds(pool, buddy)) {
            break;
        }
        // Split the block: insert buddy into the freelist
        buddy->kval = current_k;
        buddy->tag = BLOCK_AVAIL;
        insert_into_freelist(pool, buddy, current_k);
    }
    // Mark block as used and return pointer to usable memory
    block->tag = BLOCK_RESERVED;
    return (void *)(block+1); // skip over metadata
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!pool || !ptr) { // Validity check
        return;
    }
    // Convert user pointer back to block metadata.
    struct avail *block = get_block_metadata(ptr);
    // Mark the block as available.
    block->tag = BLOCK_AVAIL;

    // Attempt to merge with buddies of the same size.
    while (block->kval < pool->kval_m) {
        // Get buddy
        struct avail *buddy = buddy_calc(pool, block);
        // Check if buddy is within bounds.
        if (!can_merge(pool, buddy, block->kval)) {
            break;
        }
        // Remove buddy from the free list.
        remove_from_freelist(buddy);
        // Determine which block has the lower address
        if (buddy < block) {
            block = buddy;
        }
        // Update the block size
        block->kval++;
    }
    // Insert the merged block into the correct free list.
    insert_into_freelist(pool, block, block->kval);
}


/**
 * @brief This is a simple version of realloc.
 *
 * @param poolThe memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */
/* void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    // TODO - might do this later
    //Required for Grad Students
    //Optional for Undergrad Students
} */

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
/* static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
} */

