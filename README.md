# WinLoad

Reverse engineering the Windows 10 32 bit usermode image loader. Due to the motivation behind this project, many segments of the image loader that aren't relevant to me aren't mentioned. </br></br>
Due to much of the module directory resolution process not being applicable to my use of it, assume that members of the closely related MODULE_PATH_DATA struct may be innacurate, and confirm my findings if you plan to use it yourself. And, although I am confident in it's accuracy, take my findings in the LDRP_LOAD_CONTEXT struct with a grain of salt, as there are several unclear flags and members.

#  Credits

- [Geoffchappell.com](https://www.geoffchappell.com) - helpful in understanding and reversing undocumented or partially documented Windows structures.