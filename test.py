from colorama import init, Fore, Back, Style

class mycolors:
 reset='\033[0m'
 reverse='\033[07m'
 bold='\033[01m'
 class foreground:
  orange='\033[33m'
  blue='\033[34m'
  purple='\033[35m'
  lightgreen='\033[92m'
  lightblue='\033[94m'
  pink='\033[95m'
  lightcyan='\033[96m'
  red='\033[31m'
  green='\033[32m'
  cyan='\033[36m'
  lightgrey='\033[37m'
  darkgrey='\033[90m'
  lightred='\033[91m'
  yellow='\033[93m'
 class background:
  black='\033[40m'
  blue='\033[44m'
  cyan='\033[46m'
  lightgrey='\033[47m'
  purple='\033[45m'
  green='\033[42m'
  orange='\033[43m'
  red='\033[41m'

print(mycolors.foreground.red + "Country:\t" + "country" + mycolors.reset, end='\n')
