#!/usr/bin/env python3
"""Create a compile-only API classpath; never package its classes into app DEX."""
from pathlib import Path
import sys, zipfile
root=Path(__file__).resolve().parents[1]
source=Path(sys.argv[1])
target=root/'app/src/main/assets/compiler/android-api.jar'
target.parent.mkdir(parents=True,exist_ok=True)
temporary=target.with_suffix('.tmp')
with zipfile.ZipFile(source) as src, zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as out:
    for name in sorted(src.namelist()):
        if name.endswith('.class'):
            entry=zipfile.ZipInfo(name,(2024,1,1,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED
            out.writestr(entry,src.read(name),compresslevel=9)
temporary.replace(target)
print(target, target.stat().st_size)
