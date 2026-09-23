HASH REPORT TOOL  v1.0  -  USER GUIDE
=====================================
For internal eDiscovery use only.

WHAT IT DOES
------------
This tool creates a "digital fingerprint" (hash value) for every file in a
folder, including all subfolders. It saves the results as a spreadsheet
(CSV file) for chain-of-custody records.

The tool only READS your files. It never changes, moves, or deletes them,
and it never connects to the internet.


HOW TO USE IT
-------------
1. Double-click HashReportTool.exe.
   (Or drag a folder onto the HashReportTool.exe icon. That folder is then
   selected for you.)

2. Click "Select Folder..." and choose the folder you want to hash.

3. Tick the hash type(s) you need. MD5 is ticked by default. You can tick
   more than one (MD5, SHA-1, SHA-256). If you're not sure which one to use,
   ask your supervisor or check the ESI protocol / production specs.

4. Click "Run".
   The progress bar and status text show which file is being processed.
   Large folders can take a while. Leave the window open until it finishes.

5. When it's done, a message tells you how many files were hashed and where
   the report was saved. Click "Open Folder" to go straight to the report.


WHERE IS THE REPORT?
--------------------
The report is saved in the folder ABOVE the one you selected, so it is kept
separate from the files being hashed. For example:

   You selected:   D:\Matters\Smith\Collection01
   Report saved:   D:\Matters\Smith\Hash_Report_20260923_143015.csv

The numbers in the file name are the date and time the report was made
(YYYYMMDD_HHMMSS).

If the tool can't save there (for example, you selected a whole drive such
as E:\, or you don't have permission), it asks you where to save the report.
Don't save it inside the folder you're hashing.


WHAT'S IN THE REPORT
--------------------
The report opens in Excel. It has three parts:

1. The main table. There is one row per file, with these columns:
     File Name, Full File Path (relative to the selected folder),
     File Size (bytes), Date Modified, the hash value(s) you selected,
     Date/Time Hash Generated, Tool Version.

2. ERRORS. This lists any file the tool could NOT read, and why. The usual
   reasons are that the file is open in another program, or you don't have
   permission to read it. These files are skipped and have NO hash value.
   Close the program that is using the file (or ask IT for access), then run
   the tool again.

3. SUMMARY. This shows the source folder, file counts, the hash types used,
   start and finish times, the Windows user, and the computer name.


TIPS
----
* Don't edit the report in Excel and save over it. Excel can change how
  values look (for example, it can shorten long numbers or change date
  formats). Keep the original CSV as your record. If you want to work in
  Excel, use "Save As" to make a separate copy.
* If you close the window while the tool is still running, the report will
  be INCOMPLETE. Run the tool again.
* A folder with no errors shows "(none)" in the ERRORS section.
