from androidemu.java.jni_ref import *


class ReferenceTable:

    """
    :type _table dict[int, jobject|None]
    """
    def __init__(self, start=1, max_entries=1024):
        self._table = dict()
        self._start = start
        self._size = max_entries

    def set(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError('Expected a jobject.')

        if idx not in self._table:
            raise ValueError('Expected a index.')

        self._table[idx] = newobj


    def add(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        # Search a free index.
        index = self._start
        while index in self._table:
            index += 1

        # Add to table.
        self._table[index] = obj

        # Return local reference.
        return index

    def remove(self, obj):
        # TODO: Test
        index = None
        for i in range(self._start, self._start + len(self._table)):
            if self._table[i] is obj:
                index = i
                break

        if index is None:
            return False

        self._table[index] = None
        return True

    def get(self, idx):
        if idx not in self._table:
            return None

        return self._table[idx]

    def in_range(self, idx):
        return self._start <= idx < self._start + self._size

    def clear(self):
        self._table.clear()
