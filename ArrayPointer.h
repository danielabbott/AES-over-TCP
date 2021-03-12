#pragma once

#include "Assert.h"
#include <cstdint>

// This is an abstraction over a raw pointer.
// Use the same amount of caution as you would with any raw pointer

template<typename T, typename U = unsigned int>
class ArrayPointer {
	T * p;
	U n;

public:

	ArrayPointer(T* p_, U n_) : p(p_), n(n_) {
	}

	#define TEST() assert__(p, "Dereferenced null pointer");

	T& operator [](int i) const {
		TEST()
		assert_(i >= 0 && static_cast<U>(i) < n);
		return p[i];
	}

	bool is_null() const {
		return p == nullptr;
	}
	bool is_valid() const {
		return p != nullptr;
	}

	T* get() const {
		TEST()
		return p;
	}

	T* data() const {
		TEST()
		return p;
	}

	T* get_() const {
		return p;
	}

	U size() const {
		return n;
	}
};