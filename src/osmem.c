// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include "block_meta.h"
#include "test-utils.h"
#include "mman.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif



#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define STRUCT_SIZE (ALIGN(sizeof(struct block_meta)))

struct block_meta *head_brk, *head_mmap;

// split a block into two blocks
void split(block_meta *existing_block, size_t size)
{
	block_meta *new_block;

	// new_block represents the remaining space of the existing_block
	new_block = (block_meta *)((void *)existing_block + size + STRUCT_SIZE);

	// linking the new_block to the existing_block
	new_block->next = existing_block->next;
	new_block->prev = existing_block;
	new_block->size = existing_block->size - size - STRUCT_SIZE;
	new_block->status = STATUS_FREE;
	existing_block->next = new_block;
	existing_block->status = STATUS_ALLOC;
	existing_block->size = existing_block->size - new_block->size;
}

// coalesce two adiacent blocks with STATUS_FREE, two in one
int coalesce(block_meta *head)
{
	int ok = 0;
	block_meta *curr = head->next, *prev = head;

	while (curr) {
		if (prev->status == STATUS_FREE && curr->status == STATUS_FREE) {
			prev->size += curr->size;
			prev->next = curr->next;
			ok = 1;

			if (curr->next)
				curr->next->prev = prev;

			curr = curr->next;
			continue;
		}
		prev = curr;
		curr = curr->next;
	}
	return ok;
}


// "find fit" function
void *find_best_brk(struct block_meta *head_brk, size_t size)
{
	block_meta *curr = head_brk;
	void *best_fit = NULL;
	size_t lowest_size_that_fits = SIZE_MAX;

	// searching for the best fit and
	// storing the size of the best fit in lowest_size_that_fits
	while (curr) {
		if (curr->status == STATUS_FREE &&
			curr->size >= size &&
			curr->size <= lowest_size_that_fits) {
			lowest_size_that_fits = curr->size;
			best_fit = curr;
		}
		curr = curr->next;
	}

	if (lowest_size_that_fits == SIZE_MAX)
		return NULL;

	curr = head_brk;
	// parce the list again and return the first block that has the size
	while (curr) {
		if (curr->size == lowest_size_that_fits && curr == best_fit)
			return curr;
		curr = curr->next;
	}

	return NULL;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0)
		return NULL;


	size = ALIGN(size);

	if (size < MMAP_THRESHOLD) { // brk allocation
		// heap preallocation
		if (head_brk == NULL) { // alloc 128kb
			void *ptr = sbrk(MMAP_THRESHOLD);

			FAIL(!ptr, "Fail to allocate");

			head_brk = (struct block_meta *)ptr;
			// keeping track to the end of the heap
			head_brk->prev = ptr + MMAP_THRESHOLD;

			head_brk->status = STATUS_ALLOC;
			head_brk->size = ALIGN(size + STRUCT_SIZE);

			// if the remaining free space is larger that sizeof(struct) + 1byte
			if (head_brk->size < MMAP_THRESHOLD - STRUCT_SIZE - (STRUCT_SIZE + 8))
				split(head_brk, size);

			return ptr + STRUCT_SIZE;
		}

		// coalesce before allocating
		coalesce(head_brk);
		// finding the best fit, and if it exists, return it
		void *ptr = find_best_brk(head_brk, size + sizeof(block_meta));

		if (ptr != NULL) {
			block_meta *existing_block = (block_meta *)ptr;

			existing_block->status = STATUS_ALLOC;

			// if the remaining free space is larger that sizeof(struct) + 1byte
			if (ALIGN(existing_block->size - size - STRUCT_SIZE) >= sizeof(block_meta) + 8)
				split(existing_block, size);

			return existing_block + 1;

		} else if (ptr == NULL) {
			block_meta *curr = head_brk->prev, *prev, *tmp = head_brk;
			// searching for the last block for linking it with the new one
			while (tmp) {
				prev = tmp;
				tmp = tmp->next;
			}

			// if the last block is free, we can just extend it
			if (prev->status == STATUS_FREE) {
				head_brk->prev = sbrk(ALIGN(size - (prev->size - STRUCT_SIZE)));
				FAIL(head_brk->prev == (void *)-1, "Fail to allocate");

				// updating the end of the heap
				head_brk->prev += ALIGN(size - prev->size + STRUCT_SIZE);
				prev->size = ALIGN(size + STRUCT_SIZE);
				prev->status = STATUS_ALLOC;
				prev->next = NULL;

				return prev + 1;

			} else { // if the last block is not free, we need to allocate a new one
				head_brk->prev = sbrk(ALIGN(size + sizeof(block_meta)));
				FAIL(head_brk->prev == (void *)-1, "Fail to allocate");

				curr = head_brk->prev;
				// searching for the last block for linking it with the new one
				while (tmp) {
					prev = tmp;
					tmp = tmp->next;
				}

				// linking the new block to the last one
				prev->next = curr;
				curr->prev = prev;
				curr->next = NULL;
				curr->size = ALIGN(size + sizeof(block_meta));
				curr->status = STATUS_ALLOC;

				return curr + 1;
			}
		}
	} else if (size >= MMAP_THRESHOLD) { // mmap allocation
		block_meta *curr = head_mmap, *prev = NULL;

		while (curr) {
			prev = curr;
			curr = curr->next;
		}

		// allocating a new block
		void *ptr = mmap(NULL, ALIGN(size + sizeof(block_meta)), PROT_READ
							 | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		FAIL(!ptr, "Allocation failed :(\n)");

		curr = (block_meta *)ptr;

		// linking the new block to the last one
		curr->next = NULL;
		if (prev) {
			curr->prev = prev;
			prev->next = curr;
		} else {
			curr->prev = NULL;
			head_mmap = curr;
		}
		curr->size = ALIGN(size + sizeof(block_meta));
		curr->status = STATUS_MAPPED;

		return curr + 1;
	}
	return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	block_meta *curr, *prev;

	prev = NULL;

	curr = head_brk;
	// for sbrk
	while (curr) {
		// if the block is sbrk-ed
		if ((void *)curr + sizeof(block_meta) == ptr) {
			if (curr->status == STATUS_FREE)
				return; // error

			curr->status = STATUS_FREE;
			coalesce(head_brk);
			return;
		}
		prev = curr;
		curr = curr->next;
	}
	prev = NULL;

	curr = head_mmap;
	// for munmap
	while (curr) {
		// if the block is mapped
		if ((void *)curr + sizeof(block_meta) == ptr) {
			if (prev != NULL) {
				prev->next = curr->next;
				curr->next->prev = prev;
			} else {
				head_mmap = curr->next;
			}
			// if the block is mapped, we need to munmap it
			munmap(curr, curr->size);
			break;
		}
		prev = curr;
		curr = curr->next;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0 || nmemb == 0)
		return NULL;

	size_t page_size = getpagesize();
	size_t total_size = nmemb * size;

	size = ALIGN(total_size);

	if (size < MMAP_THRESHOLD && size + STRUCT_SIZE < page_size) { // brk allocation
		// heap preallocation
		if (head_brk == NULL) { // alloc 128kb
			void *ptr = sbrk(MMAP_THRESHOLD);

			FAIL(!ptr, "Fail to allocate");

			head_brk = (struct block_meta *)ptr;
			// keeping track to the end of the heap
			head_brk->prev = ptr + MMAP_THRESHOLD;

			head_brk->status = STATUS_ALLOC;
			head_brk->size = ALIGN(size + STRUCT_SIZE);

			// if the remaining free space is larger that sizeof(struct) + 1byte
			if (head_brk->size < 131000)
				split(head_brk, size);

			// adding the 0 char to the end of the block
			memset(ptr + STRUCT_SIZE, 0, total_size);
			return ptr + STRUCT_SIZE;
		}

		// coalesce before allocating
		coalesce(head_brk);
		// finding the best fit, and if it exists, return it
		void *ptr = find_best_brk(head_brk, size + sizeof(block_meta));

		if (ptr != NULL) {
			block_meta *existing_block = (block_meta *)ptr;

			existing_block->status = STATUS_ALLOC;
			// if the remaining free space is larger that sizeof(struct) + 1byte
			if (ALIGN(existing_block->size - size - STRUCT_SIZE) >= sizeof(block_meta) + 8)
				split(existing_block, size);

			memset(existing_block + 1, 0, total_size);
			return existing_block + 1;

		} else if (ptr == NULL) {
			block_meta *curr = head_brk->prev, *prev, *tmp = head_brk;
			// searching for the last block for linking it with the new one
			while (tmp) {
				prev = tmp;
				tmp = tmp->next;
			}

			// linking the new block to the last one
			if (prev->status == STATUS_FREE) {
				head_brk->prev = sbrk(ALIGN(size - (prev->size - STRUCT_SIZE)));
				FAIL(head_brk->prev == (void *)-1, "Fail to allocate");

				// updating the end of the heap
				head_brk->prev += ALIGN(size - prev->size + STRUCT_SIZE);
				prev->size = ALIGN(size + STRUCT_SIZE);
				prev->status = STATUS_ALLOC;
				prev->next = NULL; // nu cred ca e necesar

				// adding the 0 char to the end of the block
				memset(prev + 1, 0, total_size);
				return prev + 1;

			} else { // if the last block is not free, we need to allocate a new one
				head_brk->prev = sbrk(ALIGN(size + sizeof(block_meta)));
				FAIL(head_brk->prev == (void *)-1, "Fail to allocate");

				curr = head_brk->prev;
				// searching for the last block for linking it with the new one
				while (tmp) {
					prev = tmp;
					tmp = tmp->next;
				}

				// linking the new block to the last one
				prev->next = curr;
				curr->prev = prev;
				curr->next = NULL;
				curr->size = ALIGN(size + sizeof(block_meta));
				curr->status = STATUS_ALLOC;

				// adding the 0 char to the end of the block
				memset(curr + 1, 0, total_size);
				return curr + 1;
			}
		}
	} else { // mmap allocation
		block_meta *curr = head_mmap, *prev = NULL;

		while (curr) {
			prev = curr;
			curr = curr->next;
		}

		// allocating a new block
		void *ptr = mmap(NULL, ALIGN(size + sizeof(block_meta)), PROT_READ
							 | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		FAIL(!ptr, "Allocation failed :(\n)");

		curr = (block_meta *)ptr;

		// linking the new block to the last one
		curr->next = NULL;
		if (prev) {
			curr->prev = prev;
			prev->next = curr;
		} else {
			curr->prev = NULL;
			head_mmap = curr; // incredibil, cum sa uit sa pun asta?
		}
		curr->size = ALIGN(size + sizeof(block_meta));
		curr->status = STATUS_MAPPED;

		// adding the 0 char to the end of the block
		memset(curr + 1, 0, total_size);
		return curr + 1;
	}
	return NULL;
}

// find the block that has the ptr
block_meta *find_block(void *ptr)
{
	block_meta *curr = head_brk;

	while (curr) {
		if ((block_meta *)ptr == curr)
			return curr;

		curr = curr->next;
	}

	curr = head_mmap;
	while (curr) {
		if ((block_meta *)ptr == curr)
			return curr;

		curr = curr->next;
	}
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL) {
		ptr += STRUCT_SIZE;
		ptr = os_malloc(size);
		return ptr;
	}

	// calculating the size of the old block
	block_meta *old_ptr = (block_meta *)(ptr - STRUCT_SIZE);
	size_t old_size = old_ptr->size - STRUCT_SIZE;
	size_t copy_size = MIN(old_size, size);

	ptr -= STRUCT_SIZE;

	if (((block_meta *)ptr)->status == STATUS_FREE)
		return NULL;

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	block_meta *block;

	block = find_block(ptr);
	// coalesce blocks further from "block" block;
	if (block && block->next) {
		block->status = STATUS_FREE;
		if (coalesce(block)) {
			block->status = STATUS_ALLOC;
			return block + 1;
		}
		block->status = STATUS_ALLOC;
	}

	void *alloc;

	if (block && block->size == size + STRUCT_SIZE) {
		return block + 1;
	} else if (block && block->size < MMAP_THRESHOLD
			 && block->size >= size + STRUCT_SIZE) {
	// if we want a smaller size for our block, the memory stays in place
		if (ALIGN(block->size - size - STRUCT_SIZE) >= sizeof(block_meta) + 8)
			split(block, size);

		return block + 1;
	} // if we want to realocate a mmap block smaller than 128kb, we need brk

	alloc = os_malloc(size);
	memcpy(alloc, ptr + 32, copy_size + STRUCT_SIZE);
	os_free(ptr + STRUCT_SIZE);

	return alloc;
}
