#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H

/**********************************
Dynamic array one header library usage example:

#include "dynamic_array.h"

int main(void) {
	// Declare & init
	DYNAMIC_ARRAY_DECLARE(int, arr);
	DYNAMIC_ARRAY_INIT(arr);

	// Filling data
	DYNAMIC_ARRAY_PUSH(arr, 10);
	DYNAMIC_ARRAY_PUSH(arr, 15);
	DYNAMIC_ARRAY_PUSH(arr, 20);

	// Access
	int x = DYNAMIC_ARRAY_ITEM(arr, 1);
	int y = DYNAMIC_ARRAY_AT(arr, 0);
	int z = DYNAMIC_ARRAY_BACK(arr);

	// Insert & remove
	DYNAMIC_ARRAY_INSERT(arr, 1, 99);
	DYNAMIC_ARRAY_REMOVE(arr, 0);

	// Pop
	int last = DYNAMIC_ARRAY_POP_BACK(arr);
	DYNAMIC_ARRAY_POP(arr);

	// Work with data
	DYNAMIC_ARRAY_FOREACH(arr, i, {
		printf("%zu: %d\n", i, DYNAMIC_ARRAY_ITEM(arr, i));
	});

	// Capacity
	DYNAMIC_ARRAY_RESERVE(arr, 100);
	DYNAMIC_ARRAY_RESIZE(arr, 6);
	DYNAMIC_ARRAY_CLEAR(arr);
	DYNAMIC_ARRAY_SHRINK(arr);

	// Exit
	DYNAMIC_ARRAY_FREE(arr);

	return 0;
}
************************************/

#include <stdlib.h>
#include <string.h>

#ifdef DYNAMIC_ARRAY_USE_SYSLOG
#include <syslog.h>
#define DYNAMIC_ARRAY_ERROR(_fmt, ...) do { syslog(LOG_ERROR, _fmt, __VA_ARGS__); } while(0)
#else
#include <stdio.h>
#define DYNAMIC_ARRAY_ERROR(_fmt, ...) do { fprintf(stderr, _fmt, __VA_ARGS__); fprintf(stderr,"\n"); } while(0)
#endif

#define DYNAMIC_ARRAY_STRINGIFY(x) #x

/******************************************************************
 * Declaration & lifecycle
 ******************************************************************/

#define DYNAMIC_ARRAY_DECLARE(_type, _name) \
	struct { \
		_type* data; \
		size_t count; \
		size_t capacity; \
	} _name

#define DYNAMIC_ARRAY_INIT(_arr) \
	do { \
		(_arr).count = 0; \
		(_arr).capacity = 10; \
		(_arr).data = calloc((_arr).capacity, sizeof(*(_arr).data)); \
		if (!(_arr).data) { \
			DYNAMIC_ARRAY_ERROR("can't init array %s %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), __FILE__, __LINE__); \
			abort(); \
		} \
	} while (0)

#define DYNAMIC_ARRAY_FREE(_arr) \
	do { \
		if ((_arr).data) free((_arr).data); \
		(_arr).data = NULL; \
		(_arr).count = 0; \
		(_arr).capacity = 0; \
	} while(0)

/******************************************************************
 * Internal needs
 ******************************************************************/

#define DYNAMIC_ARRAY_GROW__(_arr, _mincap) \
	do { \
		if ((_mincap) > (_arr).capacity) { \
			size_t _arr_ncap = (_mincap) > (_arr).capacity * 2 ? (_mincap) : (_arr).capacity * 2; \
			void *_arr_p = reallocarray((_arr).data, _arr_ncap, sizeof(*(_arr).data)); \
			if (!_arr_p) { \
				DYNAMIC_ARRAY_ERROR("realloc failure for array %s %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), __FILE__, __LINE__); \
				abort(); \
			} \
			(_arr).data = _arr_p; \
			(_arr).capacity = _arr_ncap; \
		} \
	} while(0)

#define DYNAMIC_ARRAY_POP_EMPTY_WARNING__(_arr) \
	if ((_arr).count == 0) { \
		DYNAMIC_ARRAY_ERROR("array %s is empty %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), __FILE__, __LINE__); \
		abort(); \
	}

/******************************************************************
 * Accessors
 ******************************************************************/

#define DYNAMIC_ARRAY_ITEM(_arr, _iter) ((_arr).data[_iter])

#define DYNAMIC_ARRAY_AT(_arr, _index) \
	__extension__({ \
		size_t _at_idx = (_index); \
		if (_at_idx >= (_arr).count) { \
			DYNAMIC_ARRAY_ERROR("array %s index %zu out of bounds (count=%zu) %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), _at_idx, (_arr).count, __FILE__, __LINE__); \
			abort(); \
		} \
		(_arr).data[_at_idx]; \
	})

#define DYNAMIC_ARRAY_BACK(_arr) \
	__extension__({ \
		DYNAMIC_ARRAY_POP_EMPTY_WARNING__(_arr) \
		(_arr).data[(_arr).count - 1]; \
	})

#define DYNAMIC_ARRAY_EMPTY(_arr) ((_arr).count == 0)

/******************************************************************
 * Mutation
 ******************************************************************/

#define DYNAMIC_ARRAY_PUSH(_arr, _item) \
	do { \
		DYNAMIC_ARRAY_GROW__(_arr, (_arr).count + 1); \
		(_arr).data[(_arr).count++] = (_item); \
	} while (0)

#define DYNAMIC_ARRAY_POP(_arr) \
	do { \
		DYNAMIC_ARRAY_POP_EMPTY_WARNING__(_arr) \
		(_arr).count--; \
	} while (0)

#define DYNAMIC_ARRAY_POP_BACK(_arr) \
	__extension__({ \
		typeof(*(_arr).data) _pback_val; \
		DYNAMIC_ARRAY_POP_EMPTY_WARNING__(_arr) \
		_pback_val = (_arr).data[--(_arr).count]; \
		_pback_val; \
	})

#define DYNAMIC_ARRAY_REMOVE(_arr, _index) \
	do { \
		size_t _rm_idx = (_index); \
		if (_rm_idx >= (_arr).count) { \
			DYNAMIC_ARRAY_ERROR("array %s remove index %zu out of bounds (count=%zu) %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), _rm_idx, (_arr).count, __FILE__, __LINE__); \
			abort(); \
		} \
		memmove((_arr).data + _rm_idx, \
			(_arr).data + _rm_idx + 1, \
			((_arr).count - 1 - _rm_idx) * sizeof(*(_arr).data)); \
		(_arr).count--; \
	} while(0)

#define DYNAMIC_ARRAY_INSERT(_arr, _index, _item) \
	do { \
		size_t _ins_idx = (_index); \
		if (_ins_idx > (_arr).count) { \
			DYNAMIC_ARRAY_ERROR("array %s insert index %zu out of bounds (count=%zu) %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), _ins_idx, (_arr).count, __FILE__, __LINE__); \
			abort(); \
		} \
		DYNAMIC_ARRAY_GROW__(_arr, (_arr).count + 1); \
		memmove((_arr).data + _ins_idx + 1, \
			(_arr).data + _ins_idx, \
			((_arr).count - _ins_idx) * sizeof(*(_arr).data)); \
		(_arr).data[_ins_idx] = (_item); \
		(_arr).count++; \
	} while(0)

#define DYNAMIC_ARRAY_CLEAR(_arr) \
	do { \
		(_arr).count = 0; \
	} while(0)

/******************************************************************
 * Capacity
 ******************************************************************/

#define DYNAMIC_ARRAY_RESERVE(_arr, _newcap) \
	do { \
		DYNAMIC_ARRAY_GROW__(_arr, _newcap); \
	} while(0)

#define DYNAMIC_ARRAY_SHRINK(_arr) \
	do { \
		if ((_arr).count == 0) { \
			DYNAMIC_ARRAY_FREE(_arr); \
		} else if ((_arr).count < (_arr).capacity) { \
			void *_arr_p = reallocarray((_arr).data, (_arr).count, sizeof(*(_arr).data)); \
			if (!_arr_p) { \
				DYNAMIC_ARRAY_ERROR("realloc failure for array %s %s:%d", DYNAMIC_ARRAY_STRINGIFY(_arr), __FILE__, __LINE__); \
				abort(); \
			} \
			(_arr).data = _arr_p; \
			(_arr).capacity = (_arr).count; \
		} \
	} while(0)

#define DYNAMIC_ARRAY_RESIZE(_arr, _newcount) \
	do { \
		if ((_newcount) > (_arr).count) { \
			DYNAMIC_ARRAY_GROW__(_arr, (_newcount)); \
			memset((_arr).data + (_arr).count, 0, ((_newcount) - (_arr).count) * sizeof(*(_arr).data)); \
		} \
		(_arr).count = (_newcount); \
	} while(0)

/******************************************************************
 * Iteration
 ******************************************************************/

#define DYNAMIC_ARRAY_FOREACH(_arr, _iter, _body) \
	for (size_t (_iter) = 0; (_iter) < (_arr).count; (_iter)++) do { _body } while(0)

#endif /* DYNAMIC_ARRAY_H */

/*
// UNIT TEST FOR ALL FEATURES
// gcc -std=gnu11 -Wall -Wextra -pedantic -g -o test test.c 2>&1
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "dynamic_array.h"

int main(void) {
	// === DECLARE & INIT ===
	DYNAMIC_ARRAY_DECLARE(int, arr);
	DYNAMIC_ARRAY_INIT(arr);
	printf("[OK] INIT\n");

	// === PUSH ===
	DYNAMIC_ARRAY_PUSH(arr, 10);
	DYNAMIC_ARRAY_PUSH(arr, 20);
	DYNAMIC_ARRAY_PUSH(arr, 30);
	printf("[OK] PUSH 3 items, count=%zu\n", arr.count);

	// === EMPTY ===
	if (!DYNAMIC_ARRAY_EMPTY(arr))
		printf("[OK] EMPTY returns false\n");

	DYNAMIC_ARRAY_DECLARE(char, empty_arr);
	DYNAMIC_ARRAY_INIT(empty_arr);
	if (DYNAMIC_ARRAY_EMPTY(empty_arr))
		printf("[OK] EMPTY returns true for empty\n");

	// === ITEM ===
	if (DYNAMIC_ARRAY_ITEM(arr, 1) == 20)
		printf("[OK] ITEM\n");

	// === AT (in bounds) ===
	if (DYNAMIC_ARRAY_AT(arr, 0) == 10)
		printf("[OK] AT in-bounds\n");

	// === BACK ===
	if (DYNAMIC_ARRAY_BACK(arr) == 30)
		printf("[OK] BACK\n");

	// === INSERT at beginning ===
	DYNAMIC_ARRAY_INSERT(arr, 0, 5);
	if (arr.count == 4 && DYNAMIC_ARRAY_ITEM(arr, 0) == 5)
		printf("[OK] INSERT at index 0\n");

	// === INSERT at end ===
	DYNAMIC_ARRAY_INSERT(arr, arr.count, 99);
	if (arr.count == 5 && DYNAMIC_ARRAY_ITEM(arr, 4) == 99)
		printf("[OK] INSERT at end\n");

	// === INSERT in middle ===
	DYNAMIC_ARRAY_INSERT(arr, 2, 77);
	if (DYNAMIC_ARRAY_ITEM(arr, 2) == 77)
		printf("[OK] INSERT in middle\n");

	// === REMOVE ===
	DYNAMIC_ARRAY_REMOVE(arr, 0);
	if (arr.count == 5 && DYNAMIC_ARRAY_ITEM(arr, 0) == 10)
		printf("[OK] REMOVE index 0\n");

	DYNAMIC_ARRAY_REMOVE(arr, arr.count - 1);
	if (arr.count == 4)
		printf("[OK] REMOVE last\n");

	DYNAMIC_ARRAY_REMOVE(arr, 1);
	if (arr.count == 3 && DYNAMIC_ARRAY_ITEM(arr, 1) == 20)
		printf("[OK] REMOVE middle\n");

	// === POP_BACK ===
	int popped = DYNAMIC_ARRAY_POP_BACK(arr);
	if (popped == 30 && arr.count == 2)
		printf("[OK] POP_BACK returned %d\n", popped);

	// === POP ===
	DYNAMIC_ARRAY_POP(arr);
	if (arr.count == 1)
		printf("[OK] POP, count=%zu\n", arr.count);

	// === RESERVE ===
	DYNAMIC_ARRAY_RESERVE(arr, 100);
	if (arr.capacity >= 100)
		printf("[OK] RESERVE to %zu\n", arr.capacity);

	// === RESIZE (grow) ===
	DYNAMIC_ARRAY_RESIZE(arr, 5);
	if (arr.count == 5 && DYNAMIC_ARRAY_ITEM(arr, 4) == 0)
		printf("[OK] RESIZE grow, new elements zeroed\n");

	// === RESIZE (shrink) ===
	DYNAMIC_ARRAY_RESIZE(arr, 3);
	if (arr.count == 3)
		printf("[OK] RESIZE shrink\n");

	// === SHRINK ===
	DYNAMIC_ARRAY_PUSH(arr, 40);
	DYNAMIC_ARRAY_PUSH(arr, 50);
	size_t cap_before = arr.capacity;
	DYNAMIC_ARRAY_SHRINK(arr);
	if (arr.capacity < cap_before && arr.capacity == arr.count)
		printf("[OK] SHRINK capacity %zu -> %zu\n", cap_before, arr.capacity);

	// === CLEAR ===
	DYNAMIC_ARRAY_CLEAR(arr);
	if (arr.count == 0 && arr.data != NULL)
		printf("[OK] CLEAR, count=0, data preserved\n");

	// === FOREACH ===
	DYNAMIC_ARRAY_PUSH(arr, 1);
	DYNAMIC_ARRAY_PUSH(arr, 2);
	DYNAMIC_ARRAY_PUSH(arr, 3);
	size_t sum = 0;
	DYNAMIC_ARRAY_FOREACH(arr, i, {
		sum += DYNAMIC_ARRAY_ITEM(arr, i);
	});
	if (sum == 6)
		printf("[OK] FOREACH sum=%zu\n", sum);

	// === FOREACH dangling-else safe ===
	{
		int cond = 1, sum = 0;
		if (cond)
			DYNAMIC_ARRAY_FOREACH(arr, i, {
				sum += DYNAMIC_ARRAY_ITEM(arr, i);
			});
		else {
			;
		}
	}
	printf("[OK] FOREACH dangling-else safe\n");

	// === GROW on many pushes (reallocarray trigger) ===
	DYNAMIC_ARRAY_CLEAR(arr);
	for (size_t n = 0; n < 1000; n++)
		DYNAMIC_ARRAY_INSERT(arr, n, (int)n);
	if (arr.count == 1000)
		printf("[OK] 1000 INSERTs, count=%zu\n", arr.count);

	// === Test with struct type ===
	struct Point { int x; char c; };
	DYNAMIC_ARRAY_DECLARE(struct Point, sarr);
	DYNAMIC_ARRAY_INIT(sarr);
	struct Point p0 = { .x = 42, .c = 'A' };
	DYNAMIC_ARRAY_PUSH(sarr, p0);
	if (DYNAMIC_ARRAY_ITEM(sarr, 0).x == 42 && DYNAMIC_ARRAY_ITEM(sarr, 0).c == 'A')
		printf("[OK] struct type support\n");

	// === POP_BACK with struct ===
	struct Point popped_s = DYNAMIC_ARRAY_POP_BACK(sarr);
	if (popped_s.x == 42 && popped_s.c == 'A')
		printf("[OK] POP_BACK with struct\n");

	// === SHRINK on empty ===
	DYNAMIC_ARRAY_CLEAR(sarr);
	DYNAMIC_ARRAY_SHRINK(sarr);
	if (sarr.data == NULL && sarr.count == 0 && sarr.capacity == 0)
		printf("[OK] SHRINK on empty frees memory\n");

	// Cleanup
	DYNAMIC_ARRAY_FREE(arr);
	DYNAMIC_ARRAY_FREE(sarr);
	DYNAMIC_ARRAY_FREE(empty_arr);
	printf("\nAll tests passed.\n");
	return 0;
}
*/
