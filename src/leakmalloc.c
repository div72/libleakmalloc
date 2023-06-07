#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifdef TRACE
#include <unistd.h>
#endif

#define ALLOC_SIZE 128 * 1024 * 1024

static void* g_ptr_start;
static volatile atomic_uintptr_t g_ptr_cur;

#ifndef NO_DEFER_MALLOC
static void* (*next_malloc)(size_t) = NULL;
static void (*next_free)(void*) = NULL;
static void* (*next_realloc)(void*, size_t) = NULL;
#endif

__attribute__((malloc)) void* malloc(size_t size) {
#ifdef TRACE
    write(0, "malloc()\n", 9);
#endif

    // Ensure everything is aligned to 8.
    if (size & 7) {
        size &= ~7;
        size <<= 1;
    }
    void* ptr = (void*)atomic_fetch_add(&g_ptr_cur, size);

    if (ptr + size > g_ptr_start + ALLOC_SIZE) {
#ifndef NO_DEFER_MALLOC
        // We ran out of pre-allocated space, hand-over to another malloc.
        if (__builtin_expect(next_malloc == NULL, 0)) {
#ifdef TRACE
            write(0, "new_malloc()\n", 13);
#endif
            next_malloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "malloc");
        }

        return next_malloc(size);
#else
        return NULL;
#endif
    }

    return ptr;
}

__attribute__((malloc)) void* calloc(size_t num, size_t size) {
    void* ptr = malloc(num * size);

    if (ptr != NULL) {
        // TODO: data returned from our malloc should always be zero initalized.
        // This is for data that comes from next_malloc.
        // FIXME: memset segfaults?
        // memset(ptr, 0, num * size);

        for (size_t  i = 0; i < num * size; ++i) {
            *(unsigned char*)ptr = 0;
        }
    }

    return ptr;
}

void* realloc(void* ptr, size_t new_size) {
#ifndef NO_DEFER_MALLOC
    // Check if the pointer is from our malloc or next_malloc.
    if (ptr < g_ptr_start || ptr > g_ptr_start + ALLOC_SIZE) {
        if (__builtin_expect(next_realloc == NULL, 0)) {
            next_realloc = (void* (*)(void*, size_t))dlsym(RTLD_NEXT, "realloc");
        }

        return next_realloc(ptr, new_size);
    }
#endif

    void* new_ptr = malloc(new_size);
    memcpy(new_ptr, ptr, new_size);

    return new_ptr;
}

void free(void* ptr) {
#ifndef NO_DEFER_MALLOC
    // Check if the pointer is from our malloc or next_malloc.
    if (ptr < g_ptr_start || ptr > g_ptr_start + ALLOC_SIZE) {
        if (__builtin_expect(next_free == NULL, 0)) {
            next_free = (void (*)(void*))dlsym(RTLD_NEXT, "free");
        }

        return next_free(ptr);
    }
#endif
}

__attribute__((constructor)) void init_leakmalloc() {
    g_ptr_start = mmap(NULL, ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_ptr_start == (void*)-1) {
        perror("init_leakmalloc() failed: mmap() failed");
        exit(EXIT_FAILURE);
    }

    atomic_init(&g_ptr_cur, (uintptr_t)g_ptr_start);
}

