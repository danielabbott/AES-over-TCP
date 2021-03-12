#pragma once

#include <cstdint>
#include <functional>
#include "Assert.h"


// Non-resizeable array stored on the heap.
// Includes bounds checking when using at()
// Does not zero-initialise memory

template <typename T>
class HeapArray {
	inline static const char * EXCEPTION_OUT_OF_BOUNDS = "Array index out of bounds";
public:
	HeapArray(uintptr_t n) {
		ptr = new T[n];
		data_size = n;
	}

	~HeapArray() {
		if (ptr) {
			delete[] ptr;
		}
	}

	T* get() const {
		return ptr;
	}

	T* data() const {
		return ptr;
	}

	T& at(uintptr_t i) {
		assert__(i < data_size, EXCEPTION_OUT_OF_BOUNDS);
		return ptr[i];
	}

	T const& at(uintptr_t i) const {
		assert__(i < data_size, EXCEPTION_OUT_OF_BOUNDS);
		return ptr[i];
	}

	uintptr_t size() const {
		return data_size;
	}
	uintptr_t count() const {
		return data_size;
	}
	uintptr_t length() const {
		return data_size;
	}

	HeapArray(const HeapArray&) = delete;
	HeapArray& operator=(const HeapArray&) = delete;

	HeapArray(HeapArray&& other) noexcept : ptr(other.ptr), data_size(other.data_size) {
		other.ptr = nullptr;
		other.data_size = 0;
	}
	HeapArray& operator=(HeapArray&& other) noexcept {
		ptr = other.ptr;
		data_size = other.data_size;

		other.ptr = nullptr;
		other.data_size = 0;
		return *this;
	}
private:
	T* ptr;
	uintptr_t data_size; // Number of elements
};