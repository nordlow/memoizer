#include <stdio.h>

/* Compress from file `source` to file `dest` until `EOF` on `source`.

   Returns:
   - `Z_OK` on success,
   - `Z_MEM_ERROR` if memory could not be allocated for processing,
   - `Z_STREAM_ERROR` if an invalid compression level is supplied,
   - `Z_VERSION_ERROR` if the version of zlib.h and the version of the library
   linked do not match,
   - or `Z_ERRNO` if there is an error reading or writing the
   files. */
int z_compress(FILE* source, FILE* dest, int level);

/** Decompress from file `source` to file `dest` until stream ends or `EOF`.

   Returns:
   - `Z_OK` on success,
   - `Z_MEM_ERROR` if memory could not be allocated for processing,
   - `Z_DATA_ERROR` if the deflate data is invalid or incomplete,
   - `Z_VERSION_ERROR` if the version of zlib.h and the version of the library
   linked do not match, or
   - `Z_ERRNO` if there is an error reading or writing the
   files. */
int z_decompress(FILE* source, FILE* dest);
