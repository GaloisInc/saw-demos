# Overview

This repository contains a collection of demonstration proofs performed
using the Software Analysis Workbench (SAW). It contains the following
directories:

* `common`: a set of SAWScript files containing convenient common
  definitions that may be useful in a wide variety of SAW proofs.

* `templates`: a set of demonstration proof scripts that contain all of
  the key aspects that a new proof might need, with extensive comments
  explaining the structure of the script. The quickest way to start a
  new proof may be to copy one of these templates and edit it as needed.

# Getting Started

To run these examples, you'll first need to install SAW. More
information on doing so is available on the [main web site for
SAW](https://saw.galois.com). More information is also available in the
[GitHub repository](https://github.com/GaloisInc/saw-script).

SAW requires the Z3 SMT solver, and supports the use of other SMT
solvers. Since Z3 is required, we use it in these verification scripts
even though it may not be the best-performing solver.

Once SAW is installed, configure your system so that the `saw`
executable is in your shell's search path.

For C verification, the LLVM toolchain is required. In particular, the
`clang` compiler is required, and the `llvm-link` utility is necessary
for any verification involving more than one compilation unit.

For Java verification, JDK 6 through JDK 8 is required. Later versions
unfortunately do not include `.jar` file containing the standard
libraries, and SAW does not have the ability to read the pre-compiled
versions of the standard libraries that they do include.

Each of the verification demos includes a `Makefile` that will perform
whatever steps are required to compile the source code under analysis
and the execute `saw` on the appropriate verification script.
