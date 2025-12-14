#ifndef _DYNAMIC_ARRAY_H_
#define _DYNAMIC_ARRAY_H_

#ifdef DYNAMIC_ARRAY_USE_SYSLOG
#define DYN_ARR_ERROR(_fmt, ...) do { syslog(LOG_ERROR, _fmt, __VA_ARGS__); } while(0)
#else
#define DYN_ARR_ERROR(_fmt, ...) do { fprintf(stderr, _fmt, __VA_ARGS__); fprintf(stderr,"\n"); } while(0)
#endif

#define DYN_STRINGIFY(x) #x

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
			DYN_ARR_ERROR("Can't init array %s", DYN_STRINGIFY(_arr)); \
			abort(); \
		} \
	} while (0)

#define DYNAMIC_ARRAY_PUSH(_arr, _item) \
	do { \
		if ((_arr).count + 1 > (_arr).capacity) { \
			size_t _arr_newcap = (_arr).capacity * 2; \
			void *_arr_realloc = reallocarray((_arr).data, _arr_newcap, sizeof(*(_arr).data)); \
			if (!_arr_realloc) { \
				DYN_ARR_ERROR("Memory reallocation failure for array %s", DYN_STRINGIFY(_arr)); \
				abort(); \
			} \
			(_arr).data = _arr_realloc; \
			(_arr).capacity  = _arr_newcap; \
		} \
		(_arr).data[(_arr).count++] = (_item); \
	} while (0)

#define DYNAMIC_ARRAY_FREE(_arr) \
	do { \
		if ((_arr.data)) free((_arr).data); \
		(_arr).data = NULL; \
		(_arr).count = 0; \
		(_arr).capacity = 0; \
	} while(0)

#define DYNAMIC_ARRAY_FOREACH(_arr, _iter, _body) \
	for (size_t (_iter) = 0; (_iter) < (_arr).count; (_iter)++) { _body; }

#endif /* _DYNAMIC_ARRAY_H_*/
