class SyscallHandler:

    def __init__(self, idx, name, arg_count, callback):
        self.idx = idx
        self.name = name
        self.arg_count = arg_count
        self.callback = callback
