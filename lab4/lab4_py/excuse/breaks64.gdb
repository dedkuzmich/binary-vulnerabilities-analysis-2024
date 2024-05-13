# Debugger options to work with multiprocess binaries
set follow-fork-mode child
set detach-on-fork off

# Disassameble functions
disas child_job
disas main

# CHILD_JOB
# After gets()
br *child_job+87

# ZF - zero flag
# Check if ZF == 1 (if rdx contains canary, then rdx - fs:28h = 0 => ZF = 1) 
br *child_job+137

# Return
br *child_job+145


# MAIN
# Next iteration of the infinite loop
# br *main+142