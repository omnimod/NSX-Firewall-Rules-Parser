**About**
--------
This is a simple PowerShell command to parse NSX firewall rules.

**Execution**
--------
Use PowerShell commandlet Parse-NSXRules.ps1 to parse NSX XML export.

_Parse-NSXRules.ps1 -FilePath \<string\> [-ResultPath \<string\>] [-Property \<string\>] [-Format \<string\>]_

Parameters:
-  -FilePath \<string\>   - (mandatory) Specify path to the pcoip_server log file.
-  -ResultPath \<string\> - (mandatory) Specify path to export results to the file.
-  -Property \<string\> - (optional) Select properties to display, separated by commas.
-  -Format \<string\>     - (optional) Specify the report format. Supported values are: CSV, HTML or TEXT. By default data is saved in the TEXT format.

Examples:

  #Parse XML file and export result as a HTML file
  
  _.\parse-nsxrules.ps1 -FilePath C:\Temp\NSX_rules.xml -Format HTML -ResultPath C:\Temp\parsed_rules.html_
  
  #Parse XML file and export result as a CSV file, select only id,name,source and action columns
  
  _.\parse-nsxrules.ps1 -FilePath C:\Temp\NSX_rules.xml -Format CSV -ResultPath C:\Temp\parsed_rules.csv -Property "id,name,source,action"_

**Releases**
--------

v1.0 - Initial release.

**Known issues**
--------
1. Current version does not parse L2 firewall rules.

**Licensing**
-------
The MIT License

Copyright 2018 https://blog.vmpress.org

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
