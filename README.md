<!-- #######  THIS IS A COMMENT - Visible only in the source editor #########-->
# PyIntelOwl-Parser
<p><span data-preserver-spaces="true">I have created this parser for Pylntel, which is the CLI tool for IntelOwl.</span></p>
<p><span data-preserver-spaces="true">IntelOwl is what I was looking for as an Intel analyst to check indicators across multiple sources at the same quickly.</span></p>
<p><span data-preserver-spaces="true">Intelowl can be configured to reach out to VirusTotal, Hybrid Analysis etc. and return a JSON file as a result. Intelowl effectively provides an API to rule them all. All this "plugin" parser does, is to parse the JSON file colourfully returned by Intelowl, which is easier to read.&nbsp;</span></p>
<p>&nbsp;</p>

## Installation

<ol>
<li><span data-preserver-spaces="true">Install IntelOwl (Got to the official repository <a href="https://github.com/intelowlproject/IntelOwl">here</a> and follow the instructions. The instructions are very simple, you just need to clone the repo, have docker and docker-compose installed, set up the environment files as requested in the docs and execute docker-compose run.)</span></li>
<li><span data-preserver-spaces="true">Generate your api and paste it in file "api_token.txt"</span></li>
<li><span data-preserver-spaces="true">Git clone https://github.com/tsale/PyIntelOwl-Parser.git</span></li>
<li><span data-preserver-spaces="true">pip install colorama <span id="pip-command">geocoder</span></span></li>
<li>Use it on a terminal that supports different colour outputs</li>
</ol>
<p>&nbsp;</p>

### Command line Client

<p>Instructions on how to run the script has been taken from the original PyIntelOwl repo (<a href="https://github.com/intelowlproject/pyintelowl">https://github.com/intelowlproject/pyintelowl</a>)</p>
<h4><a id="user-content-help" class="anchor" href="https://github.com/intelowlproject/pyintelowl#help" aria-hidden="true"></a>Help</h4>
<p><code>python3 intel_owl_client.py -h</code></p>
<h4><a id="user-content-analyze" class="anchor" href="https://github.com/intelowlproject/pyintelowl#analyze" aria-hidden="true"></a>Analyze</h4>
<p>2 Submodules:&nbsp;<code>file</code>&nbsp;and&nbsp;<code>observable</code></p>
<h5><a id="user-content-sample" class="anchor" href="https://github.com/intelowlproject/pyintelowl#sample" aria-hidden="true"></a>Sample</h5>
<p>Example:</p>
<p><code>python3 intel_owl_client.py -k &lt;api_token_file&gt; -i &lt;url&gt; -a PE_Info -a File_Info file -f &lt;path_to_file&gt;</code></p>
<p>Run all available analyzers (some of them could fail if you did not implement the required configuration in the IntelOwl server):</p>
<p><code>python3 intel_owl_client.py -k &lt;api_token_file&gt; -i &lt;url&gt; -aa file -f &lt;path_to_file&gt;</code></p>
<h5><a id="user-content-observable" class="anchor" href="https://github.com/intelowlproject/pyintelowl#observable" aria-hidden="true"></a>Observable</h5>
<p>Example:</p>
<p><code>python3 intel_owl_client.py -k &lt;api_token_file&gt; -i &lt;url&gt; -a AbuseIPDB -a OTXQuery observable -v google.com</code></p>
<p>&nbsp;</p>

## Current parser capabilities

<p><span data-preserver-spaces="true">Currently, I am only parsing the results returned for the services below for the equivalent observables.</span></p>
<p>&nbsp;</p>
<p><span style="text-decoration: underline;">Domains</span></p>
<ul>
<li><span data-preserver-spaces="true">VirusTotal</span></li>
<li><span data-preserver-spaces="true">Hybrid Analysis</span></li>
<li><span data-preserver-spaces="true">OTXQuery</span></li>
</ul>
<p>&nbsp;</p>
<p><span style="text-decoration: underline;">Hash</span></p>
<ul>
<li><span data-preserver-spaces="true">VirusTotal</span></li>
<li><span data-preserver-spaces="true">Hybrid Analysis</span></li>
<li><span data-preserver-spaces="true">OTXQuery</span></li>
</ul>
<p>&nbsp;</p>
<p><span style="text-decoration: underline;">IP</span></p>
<ul>
<li><span data-preserver-spaces="true">Virustotal</span></li>
<li><span data-preserver-spaces="true">Hybrid Analysis</span></li>
<li><span data-preserver-spaces="true">OTXQuery</span></li>
<li><span data-preserver-spaces="true">AlouselPDB</span></li>
<li><span data-preserver-spaces="true">Lencys_Search</span></li>
<li><span data-preserver-spaces="true">Grey Noise</span></li>
</ul>
<p>&nbsp;</p>
<p><span data-preserver-spaces="true">If you like the idea but not the execution, feel free to improve the parser and drop me a note with the changes. Personally, it does the job, and it's useful for my intended use.</span></p>
<p>&nbsp;</p>

## Running Examples:

![Example 1](https://github.com/tsale/PyIntelOwl-Parser/blob/master/Images/InteOwl_parser-1.PNG)

![Example 2](https://github.com/tsale/PyIntelOwl-Parser/blob/master/Images/InteOwl_parser-2.PNG)

![Example 3](https://github.com/tsale/PyIntelOwl-Parser/blob/master/Images/InteOwl_parser-3.PNG)

![Example 4](https://github.com/tsale/PyIntelOwl-Parser/blob/master/Images/InteOwl_parser-4.PNG)

![Example 5](https://github.com/tsale/PyIntelOwl-Parser/blob/master/Images/InteOwl_parser-5.PNG)


