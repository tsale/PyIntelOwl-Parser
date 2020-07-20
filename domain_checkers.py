from colorama import init, Fore, Back, Style
import geocoder
from datetime import datetime
import os




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

class Checkers:
    def check_domain(results,value):
        vt = {}
        ha = {}
        otx = {}
        for i in results:
            if 'HybridAnalysis_Get_Observable' in i['name']:
                ha.update(i)   
            elif 'VirusTotal_v2_Get_Observable' in i['name']:
                vt.update(i)               
            elif "OTXQuery" in i['name']:
                otx.update(i)
              
        if vt:
            try:
                if "VirusTotal_v2" in vt['name']:
                    Domains.vtDomaincheck(vt['report'],value)
            except KeyError:
                print(mycolors.foreground.lightred + "\nERROR: Try using VirusTotal_v2_Get_Observable instead!\n")
        if ha:
            Domains.haDomaincheck(ha['report'])
        if otx:
            Domains.otxDomaincheck(otx['report'])
            
    def check_hash(results):
        vt = {}
        ha = {}
        otx = {}
        for i in results:
            if 'HybridAnalysis_Get_Observable' in i['name']:
                ha.update(i)   
            elif 'VirusTotal_v3_Get_Observable' in i['name']:
                vt.update(i)               
            elif "OTXQuery" in i['name']:
                otx.update(i)        
                
        if vt:
            if "VirusTotal_v3" in vt['name']:
                Hashes.vthash(vt['report'])
            else:
                print(mycolors.foreground.lightred + "\nERROR: Try using VirusTotal_v3_Get_Observable instead!\n")
        if ha:
            Hashes.hahash(ha['report'])
        if otx:
            Hashes.otxhash(otx['report'])
            
    def check_ip(results,value):
        vt = {}
        ha = {}
        otx = {}
        abusedb = {}
        censys = {}
        greynoise = {}
        for i in results:
            if 'HybridAnalysis_Get_Observable' in i['name']:
                ha.update(i)   
            elif 'VirusTotal_v2_Get_Observable' in i['name']:
                vt.update(i)               
            elif "OTXQuery" in i['name']:
                otx.update(i)
            elif "AbuseIPDB" in i['name']:
                abusedb.update(i)
            elif "Censys_Search" in i['name']:
                censys.update(i)
            elif "GreyNoiseAlpha" in i['name']:
                greynoise.update(i)
        
        
        if abusedb:
            IPs.abIPdbcheck(abusedb['report']['data'])
        if censys:
            IPs.censysIPcheck(censys['report'])
        if greynoise:
            IPs.gnoiseIPcheck(greynoise['report'])
        if vt:
            try:
                if "VirusTotal_v2" in vt['name']:
                    IPs.vtIPcheck(vt['report'],value)
            except KeyError:
                print(mycolors.foreground.lightred + "\nERROR: Try using VirusTotal_v2_Get_Observable instead!\n")
            
        if ha:
            IPs.haIPcheck(ha['report'])
        if otx:
            IPs.otxIPcheck(otx['report'])    

               
class Domains:
    def vtDomaincheck(vttext,value):
        try:
            print(mycolors.reset)
            print("\n\tDOMAIN SUMMARY REPORT")
            print("-"*20,"\n")
    
            
            print(mycolors.foreground.lightblue,mycolors.background.lightgrey)
            print("\nVIRUSTOTAL SUMMARY")
            print("-"*20) 
            print(mycolors.reset)            

    
            if 'undetected_referrer_samples' in vttext:
                print(mycolors.foreground.lightcyan + "Undetected Referrer Samples: ".ljust(17))
                if (bool(vttext['undetected_referrer_samples'])):
                    try:
                        for i in range(0, len(vttext['undetected_referrer_samples'])):
                            if (vttext['undetected_referrer_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(f"Date: {vttext['undetected_referrer_samples'][i]['date']}")
                            if (vttext['undetected_referrer_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(f"Positives: {vttext['undetected_referrer_samples'][i]['positives']}")
                            if (vttext['undetected_referrer_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(f"Total: {vttext['undetected_referrer_samples'][i]['total']}")
                            if (vttext['undetected_referrer_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print((f"SHA256: {vttext['undetected_referrer_samples'][i]['sha256']}"), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass
    
    
    

    
            if 'detected_referrer_samples' in vttext:
                print("-"*20)
                print(mycolors.foreground.pink + "Detected Referrer Samples: ".ljust(17))                
                if (bool(vttext['detected_referrer_samples'])):
                    try:
                        for i in range(len(vttext['detected_referrer_samples'])):
                            if (vttext['detected_referrer_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(f"Date: {vttext['detected_referrer_samples'][i]['date']}")
                            if (vttext['detected_referrer_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(f"Positives: {vttext['detected_referrer_samples'][i]['positives']}")
                            if (vttext['detected_referrer_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(f"Total: {vttext['detected_referrer_samples'][i]['total']}")
                            if (vttext['detected_referrer_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print((f"SHA256: {vttext['detected_referrer_samples'][i]['sha256']}"), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass
    
    
            print("-"*20)
            print(mycolors.foreground.yellow + "\nWhois Timestamp: ".ljust(17))
    
            if 'whois_timestamp' in vttext:
                if (bool(vttext['whois_timestamp'])):
                    try:
                        print("".ljust(28), end=' ') 
                        ts = vttext['whois_timestamp']
                        print((datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:{}')))
                    except KeyError as e:
                        pass
    
    

    
            if 'undetected_downloaded_samples' in vttext:
                print("-"*20)
                print(mycolors.foreground.lightgreen + "\nUndetected Downld. Samples: ".ljust(17))                
                if (bool(vttext['undetected_downloaded_samples'])):
                    try:
                        for i in range(len(vttext['undetected_downloaded_samples'])):
                            if (vttext['undetected_downloaded_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(f"Date: {vttext['undetected_downloaded_samples'][i]['date']}")
                            if (vttext['undetected_downloaded_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(f"Positives: {vttext['undetected_downloaded_samples'][i]['positives']}")
                            if (vttext['undetected_downloaded_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(f"Total: {vttext['undetected_downloaded_samples'][i]['total']}")
                            if (vttext['undetected_downloaded_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print((f"SHA256: {vttext['detected_referrer_samples'][i]['sha256']}"), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass
    
            
    
            if 'detected_downloaded_samples' in vttext:
                print("-"*20)
                print(mycolors.foreground.orange + "\nDetected Downloaded Samples: ".ljust(17))                
                if (bool(vttext['detected_downloaded_samples'])):
                    try:
                        for i in range(len(vttext['detected_downloaded_samples'])):
                            if (vttext['detected_downloaded_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(f"Date: {vttext['detected_downloaded_samples'][i]['date']}")
                            if (vttext['detected_downloaded_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(f"Positives: {vttext['detected_downloaded_samples'][i]['positives']}")
                            if (vttext['detected_downloaded_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(f"total: {vttext['detected_downloaded_samples'][i]['total']}")
                            if (vttext['detected_downloaded_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print(f"sha256: {vttext['detected_downloaded_samples'][i]['sha256']}", end=' ')
                            print("\n")
                    except KeyError as e:
                        pass
                    
            
            
                              
            if 'detected_communicating_samples' in vttext:
                print("-"*20)                
                print(mycolors.foreground.lightcyan + "\nDetected Communicating Samples: \n".ljust(17))  
                if (bool(vttext['detected_communicating_samples'])):
                    try:
                        for i in range(0, len(vttext['detected_communicating_samples'])):
                            if (vttext['detected_communicating_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(f"Date: {vttext['detected_communicating_samples'][i]['date']}")
                            if (vttext['detected_communicating_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(f"Positives: {vttext['detected_communicating_samples'][i]['positives']}")
                            if (vttext['detected_communicating_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(f"Total: {vttext['detected_communicating_samples'][i]['total']}")
                            if (vttext['detected_communicating_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print((f"SHA256: {vttext['detected_communicating_samples'][i]['sha256']}"), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass            
    
            
    
            if 'resolutions' in vttext:
                print("-"*20)
                print(mycolors.foreground.lightred + "Resolutions: ".ljust(17))                
                if (bool(vttext['resolutions'])):
                    try:
                        for i in range(len(vttext['resolutions'])):
                            if (vttext['resolutions'][i].get('last_resolved')):
                                print("".ljust(28), end=' ')
                                print(f"Last resolved: {vttext['resolutions'][i]['last_resolved']}")
                            if (vttext['resolutions'][i].get('ip_address')):
                                print("".ljust(28), end=' ')
                                print("IP address:   {}".format(vttext['resolutions'][i]['ip_address']), end=' ')
                                print("\t" + f"(City:{geocoder.ip(vttext['resolutions'][i]['ip_address']).city})")
                            print("\n")
                    except KeyError as e:
                        pass
    

    
            if 'subdomains' in vttext:
                print("-"*20)
                print(mycolors.foreground.lightgreen + "\nSubdomains: ".ljust(17))                
                if (bool(vttext['subdomains'])):
                    try:
                        for i in range(len(vttext['subdomains'])):
                            print("".ljust(28), end=' ') 
                            print((vttext['subdomains'][i]))
                    except KeyError as e:
                        pass
    
            
    
            if 'categories' in vttext:
                print("-"*20)                
                print(mycolors.foreground.lightcyan + "\nCategories: ".ljust(17))                
                if (bool(vttext['categories'])):
                    try:
                        for i in range(len(vttext['categories'])):
                            print("".ljust(28), end=' ')
                            print((vttext['categories'][i]))
                    except KeyError as e:
                        pass
    
    

    
            if 'domain_sublings' in vttext:
                print("-"*20)
                print(mycolors.foreground.lightcyan + "\nDomain Siblings: ".ljust(17))                
                if (bool(vttext['domain_sublings'])):
                    try:
                        for i in range(len(vttext['domain_siblings'])):
                            print("".ljust(28), end=' ')
                            print((vttext['domain_siblings'][i]), end=' ')
                        print("\n")
                    except KeyError as e:
                        pass
    
            

    
            if 'detected_urls' in vttext:
                print("-"*20)
                print(mycolors.foreground.yellow + "\nDetected URLs: ".ljust(17))                
                if (bool(vttext['detected_urls'])):
                    try:
                        for i in range(len(vttext['detected_urls'])):
                            if (vttext['detected_urls'][i].get('url')):
                                print("".ljust(28), end=' ')
                                print(("url: {}".format( vttext['detected_urls'][i]['url'])))
                            if (vttext['detected_urls'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("{}Positives: {}{}".format(mycolors.reset,mycolors.foreground.lightred,vttext['detected_urls'][i]['positives'])+mycolors.foreground.yellow))
                            if (vttext['detected_urls'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("{}Total: {}{}".format(mycolors.reset,mycolors.foreground.lightgreen,vttext['detected_urls'][i]['total'])+mycolors.foreground.yellow))
                            if (vttext['detected_urls'][i].get('scan_date')):
                                print("".ljust(28), end=' ')
                                print("scan_date: {}".format( vttext['detected_urls'][i]['scan_date']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass
    

    
            if 'undetected_urls' in vttext:
                print("-"*20)
                print(mycolors.foreground.lightred + "\nUndetected URLs: ".ljust(17))                
                if (bool(vttext['undetected_urls'])):
                    try:
                        for i in range(len(vttext['undetected_urls'])):
                            print((mycolors.foreground.red + "".ljust(28)), end=' ')
                            print(("Data {}\n".format( i)))
                            for y in range(len(vttext['undetected_urls'][i])):
                                print((mycolors.foreground.lightgreen + "".ljust(28)), end=' ')
                                if (y == 0):
                                    print(("url:       "), end=' ')
                                if (y == 1):
                                    print(("sha256:    "), end=' ')
                                if (y == 2):
                                    print(("positives: "), end=' ')
                                if (y == 3):
                                    print(("total:     "), end=' ')
                                if (y == 4):
                                    print(("date:      "), end=' ')
                                print(vttext['undetected_urls'][i][y])
                        print("\n")
                    except KeyError as e:
                        pass
    
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            
    
    def haDomaincheck(hatext):
        try:
            print(mycolors.foreground.lightred,mycolors.background.lightgrey)
            print("\nHYBRIDANALYSIS SUMMARY")
            print("-"*20) 
            print(mycolors.reset)     
            
            print(mycolors.foreground.orange + "\nResults found: {}".format((hatext["count"])))
            print("-"*28)
            print(mycolors.reset)
            try:
                for i in range(len(hatext['result'])): 
                    if hatext['result'][i]['verdict'] != None:
                        print(mycolors.foreground.orange, "Verdict    => " + hatext['result'][i]['verdict'])
                    
                    print(mycolors.foreground.orange, "SHA256     => " + hatext['result'][i]['sha256'])
                    if hatext['result'][i]['av_detect'] != None:
                        print(mycolors.foreground.orange, "AV Detect  => " + hatext['result'][i]['av_detect'])
                    if hatext['result'][i]['vx_family'] != None:
                        print(mycolors.foreground.orange, "Mal Family => " + hatext['result'][i]['vx_family'])
                    if hatext['result'][i]['submit_name'] != None:
                        print(mycolors.foreground.orange, "FileName   => " + hatext['result'][i]['submit_name'])
                    if hatext['result'][i]['type_short'] != None:
                        print(mycolors.foreground.orange, "FileType   => " + hatext['result'][i]['type_short'] + "\n")
            except KeyError as e:
                pass     
            
        
            
            
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to HybridAnalysis!\n"))
            print(mycolors.reset)
        except KeyError:
            print(mycolors.foreground.lightred + "\nNo results found for HYBRIDANALYSIS")    
            print(mycolors.reset)
       
            
    
    def otxDomaincheck(otxtext):
        try:
            print(mycolors.foreground.lightblue + mycolors.background.cyan)
            print("\nOTXQuery SUMMARY")
            print("-"*20,'n') 
            print(mycolors.reset)            
            
            # Get General Info
            if (bool(otxtext['pulses'])):
                try:
                    print("-"*40)
                    num = 0
                    for i in range(0, len(otxtext['pulses'])):
                        if (otxtext['pulses'][i].get('name')):
                            num +=1
                            print("".ljust(28), end=' ')
                            print(f"Data {mycolors.foreground.orange}{num}")
                            print("".ljust(28), end=' ')                            
                            print(("Name: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['name'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('tags')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Tags: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['tags'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('targeted_countries')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Targeted Countries: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['targeted_countries'],mycolors.reset)))                                
                        if (otxtext['pulses'][i].get('references')):
                            print("".ljust(28), end=' ')
                            print(mycolors.foreground.orange + "References: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['references'],mycolors.reset), end=' ')
                        print("\n")
                except KeyError as e:
                    pass     
                
                
                print("-"*20)
                # Get OTX domain detected malware samples
                print(mycolors.foreground.lightred + "\nDetected malware samples: ".ljust(17))                
                if 'malware_samples' in otxtext:
                    if (bool(otxtext['malware_samples'])):
                        try:
                            for i in range(0, len(otxtext['malware_samples'])):
                                if (otxtext['malware_samples'][i]):
                                    print("".ljust(28), end=' ')
                                    print(otxtext['malware_samples'][i])                    
                        except KeyError as e:
                            pass     
                    else:
                        print("".ljust(28), end=' ')
                        print(mycolors.reset,"NONE")
                
                
                print("-"*20)
                # Get OTX domain detected URLs
                print(mycolors.foreground.lightcyan + "\nDetected URLs: ".ljust(17))  
                if 'url_list' in otxtext:
                    if (bool(otxtext['url_list'])):
                        try:
                            for i in range(0, len(otxtext['url_list'])):
                                if (otxtext['url_list'][i]).get('url'):
                                    print("".ljust(28), end=' ')
                                    print(otxtext['url_list'][i]['url'])                    
                        except KeyError as e:
                            pass    
                    else:
                        print("".ljust(28), end=' ')
                        print(mycolors.reset,"NONE")
                
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to OTX_Query!\n"))
            print(mycolors.reset)
        except KeyError:
            print(mycolors.foreground.lightred + "\nNo results found for OTX_Query")    
            print(mycolors.reset)
              
        

class IPs:
    def abIPdbcheck(abusetext):
        print(mycolors.foreground.lightgreen,mycolors.background.lightgrey)
        print("\nABUSEIPDB SUMMARY")
        print("-"*25,"\n") 
        print(mycolors.reset) 
        
        print(mycolors.foreground.lightcyan)    
        if  abusetext['isp'] != None:
            print("".ljust(28), end=' ')            
            print("ISP: {}".format((abusetext['isp'])))
        if abusetext['domain'] != None:
            print("".ljust(28), end=' ')                        
            print("Domain: =>\t{}".format((abusetext['domain'])))
        if abusetext['usageType'] != None:
            print("".ljust(28), end=' ')                        
            print("IP usage_type: =>\t{}".format((abusetext['usageType'])))
        if abusetext['countryName'] != None:
            print("".ljust(28), end=' ')                        
            print("Country Name: =>\t{}".format((abusetext['countryName'])))        
            
    
    def gnoiseIPcheck(gnoisetext):
        print(mycolors.foreground.lightblue,mycolors.background.lightgrey)
        print("\nGREY_NOISE SUMMARY")
        print("-"*25,"\n")   
        print(mycolors.reset)
        

        try:
            print(mycolors.foreground.orange + "\nResults found: {}".format((gnoisetext['returned_count'])))
            print("-"*28)
            print(mycolors.reset)        
            print(mycolors.foreground.lightgrey)            
            for i in range(len(gnoisetext['records'])):
                if gnoisetext['records'][i]['name'] != None:
                    print("\nRecord:\t=>\t{}".format((gnoisetext['records'][i]['name'])))
                if gnoisetext['records'][i]['metadata'] != None:
                    print("".ljust(20), end=' ')                                            
                    print("Tor:\t=>\t{}".format((gnoisetext['records'][i]['metadata']['tor'])))                
                if gnoisetext['records'][i]['confidence'] != None:
                    print("".ljust(20), end=' ')                                            
                    print("Confidence:\t=>\t{}".format((gnoisetext['records'][i]['confidence'])))     
                if gnoisetext['records'][i]['last_updated'] != None:
                    print("".ljust(20), end=' ')                                            
                    print("Last_updated:\t=>\t{}".format((gnoisetext['records'][i]['last_updated'])))                 
        
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to GreyNoise!\n"))
            print(mycolors.reset)
        except KeyError:
            print(mycolors.foreground.lightred + "\nNo results found for GreyNoise")    
            print(mycolors.reset)                    
        
    
    
    def censysIPcheck(censystext):
        print(mycolors.reset)
        print("".ljust(20), end=' ')                        
        print("\n\nIP ADDRESS SUMMARY REPORT")
        print("-"*25,"\n\n",mycolors.reset)
        
        print(mycolors.foreground.lightred,mycolors.background.lightgrey)
        print("\nCENSYS_IP SUMMARY")
        print("-"*25,"\n") 
        print(mycolors.reset)        
        

        for i in censystext['protocols']:
            print(mycolors.foreground.yellow)
            print("Services running: ")            
            print("".ljust(28), end=' ')
            print(i)
            
        print("\nLast updated: {}".format((censystext['updated_at'])))
        print("-"*40,"\n") 
        
    
    def vtIPcheck(vttext,value):
        bkg = 1
        try:
            print(mycolors.reset)
            print("".ljust(20), end=' ')                        
            print("\n\nIP ADDRESS SUMMARY REPORT")
            print("-"*25,"\n\n",mycolors.reset)     
            
            

    
            if 'resolutions' in vttext:
                print(mycolors.foreground.yellow + "\nResolutions")
                print("-" * 11)
                print(mycolors.reset)                
                num = 0
                if (vttext['resolutions']):
                    for i in vttext['resolutions']:
                        if num >= 6:
                            print(mycolors.foreground.lightgreen + "\n......" + mycolors.reset)
                            print(mycolors.foreground.green + f"\nToo many resolutions... Check the website at https://www.virustotal.com/gui/ip-address/{value}/relations *** " + mycolors.reset)
                            break                    
                        elif (bkg == 1):
                            print(mycolors.foreground.lightgreen + "\nLast Resolved:\t" + i['last_resolved'] + mycolors.reset)
                            print(mycolors.foreground.lightgreen + "Hostname:\t" + i['hostname'] + mycolors.reset)
                            num +=1
                        else:
                            print(mycolors.foreground.green + "\nLast Resolved:\t" + i['last_resolved'] + mycolors.reset)
                            print(mycolors.foreground.green + "Hostname:\t" + i['hostname'] + mycolors.reset)
    

    
            if 'detected_urls' in vttext:
                print(mycolors.reset + "\nDetected URLs")
                print("-" * 13)                
                num = 0
                for j in vttext['detected_urls']:
                    if num >= 6:
                        print(mycolors.foreground.lightred + "\n......" + mycolors.reset)
                        print(mycolors.foreground.green + f"\n *** Too many Detected URLs... Check the website at https://www.virustotal.com/gui/ip-address/{value}/relations *** " + mycolors.reset)
                        break                
                    elif (bkg == 0):
                        print(mycolors.foreground.cyan + "\nURL:\t\t{}".format(j['url']) + mycolors.reset)
                        print(mycolors.foreground.cyan + "Scan Date:\t{}".format(j['scan_date'])+ mycolors.reset)
                        print(mycolors.foreground.cyan + "Positives:\t{}".format(j['positives'])+ mycolors.reset)
                        print(mycolors.foreground.cyan + "Total:\t\t{}".format(j['total'])+ mycolors.reset)
                    else:
                        print(mycolors.foreground.lightred + "\nURL:\t\t{}".format(j['url']) + mycolors.reset)
                        print(mycolors.foreground.lightred + "Scan date:\t{}".format(j['scan_date']), mycolors.reset)
                        print(mycolors.foreground.lightred + "Positives:\t{}".format(j['positives']), mycolors.reset)
                        print(mycolors.foreground.lightred + "Total:\t\t{}".format(j['total'] ), mycolors.reset)
                        num +=1
    

    
            if 'detected_downloaded_samples' in vttext:
                print(mycolors.reset + "\nDetected Downloaded Samples")
                print("-" * 27)                
                num = 0
                for k in vttext['detected_downloaded_samples']:
                    if num >= 6:
                        print(mycolors.foreground.yellow + "\n......" + mycolors.reset)
                        print(mycolors.foreground.green + f"\n *** Too many Detected Downloaded Samples... Check the website at https://www.virustotal.com/gui/ip-address/{value}/relations *** " + mycolors.reset)
                        break                
                    elif (bkg == 0):
                        print(mycolors.foreground.red + "\nSHA256:\t\t{}".format( k['sha256']) + mycolors.reset)
                        print(mycolors.foreground.red + "Date:\t\t{}".format( k['date']) + mycolors.reset)
                        print(mycolors.foreground.red + "Positives:\t%d".format( k['positives']) + mycolors.reset)
                        print(mycolors.foreground.red + "Total:\t\t%d".format( k['total']) + mycolors.reset)
                    else:
                        print(mycolors.foreground.yellow + "\nSHA256:\t\t{}".format( k['sha256']) + mycolors.reset)
                        print(mycolors.foreground.yellow + "Date:\t\t{}".format( k['date']) + mycolors.reset)
                        print(mycolors.foreground.yellow + "Positives:\t%d".format( k['positives']) + mycolors.reset)
                        print(mycolors.foreground.yellow + "Total:\t\t%d".format( k['total']) + mycolors.reset)
                        num += 1
    
    
        except ValueError:
            if(bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
                print(mycolors.reset)
    
    def haIPcheck(hatext):
        try:
            print(mycolors.foreground.lightred,mycolors.background.lightgrey)
            print("\nHYBRIDANALYSIS SUMMARY")
            print("-"*25,"\n") 
            print(mycolors.reset)     
            
            print(mycolors.foreground.orange + "\nResults found: {}".format(hatext["count"]))
            print("-"*28)
            print(mycolors.reset)
            try:
                for i in range(len(hatext['result'])): 
                    if hatext['result'][i]['verdict'] != None:
                        print(mycolors.foreground.orange, "Verdict    => " + hatext['result'][i]['verdict'])
                    
                    print(mycolors.foreground.orange, "SHA256     => " + hatext['result'][i]['sha256'])
                    if hatext['result'][i]['av_detect'] != None:
                        print(mycolors.foreground.orange, "AV Detect  => " + hatext['result'][i]['av_detect'])
                    if hatext['result'][i]['vx_family'] != None:
                        print(mycolors.foreground.orange, "Mal Family => " + hatext['result'][i]['vx_family'])
                    print(mycolors.foreground.orange, "FileName   => " + hatext['result'][i]['submit_name'])
                    if hatext['result'][i]['type_short'] != None:
                        print(mycolors.foreground.orange, "FileType   => " + hatext['result'][i]['type_short'] + "\n")
            except KeyError as e:
                pass     
            
        
            
            
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to HybridAnalysis!\n"))
            print(mycolors.reset)
        except KeyError:
            print(mycolors.foreground.lightred + "\nNo results found for HYBRIDANALYSIS")    
            print(mycolors.reset)  
            
    
    def otxIPcheck(otxtext):
        try:
            print(mycolors.foreground.lightblue + mycolors.background.lightgrey)
            print("\nOTXQuery SUMMARY")
            print("-"*25,"\n") 
            print(mycolors.reset)            
            print(mycolors.foreground.lightcyan + "General Info: ".ljust(17))
            
            # Get General Info
            if (bool(otxtext['pulses'])):
                try:
                    print("-"*40)
                    num = 0
                    for i in range(0, len(otxtext['pulses'])):
                        if (otxtext['pulses'][i].get('name')):
                            num +=1
                            print("".ljust(28), end=' ')
                            print(f"Data {mycolors.foreground.orange}{num}")
                            print("".ljust(28), end=' ')                            
                            print(("Name: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['name'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('tags')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Tags: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['tags'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('targeted_countries')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Targeted Countries: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['targeted_countries'],mycolors.reset)))                                
                        if (otxtext['pulses'][i].get('references')):
                            print("".ljust(28), end=' ')
                            print(mycolors.foreground.orange + "References: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['references'],mycolors.reset), end=' ')
                        print("\n")
                except KeyError as e:
                    pass     
                
                
                print("-"*20)
                # Get OTX IP detected malware samples
                print(mycolors.foreground.lightred + "\nDetected malware samples: ".ljust(17))                
                if 'malware_samples' in otxtext:
                    if (bool(otxtext['malware_samples'])):
                        try:
                            for i in range(0, len(otxtext['malware_samples'])):
                                if (otxtext['malware_samples'][i]):
                                    print("".ljust(28), end=' ')
                                    print(("{}".format( otxtext['malware_samples'][i])))                    
                        except KeyError as e:
                            pass     
                    else:
                        print("".ljust(28), end=' ')
                        print(mycolors.reset,"NONE")
                
                
                print("-"*20)
                # Get OTX IP detected URLs
                print(mycolors.foreground.lightcyan + "\nDetected URLs: ".ljust(17))  
                if 'url_list' in otxtext:
                    if (bool(otxtext['url_list'])):
                        try:
                            for i in range(0, len(otxtext['url_list'])):
                                if (otxtext['url_list'][i]).get('url'):
                                    print("".ljust(28), end=' ')
                                    print(("{}".format( otxtext['url_list'][i]['url'])))                    
                        except KeyError as e:
                            pass    
                    else:
                        print("".ljust(28), end=' ')
                        print(mycolors.reset,"NONE")
                
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to OTX_Query!\n"))
            print(mycolors.reset)
        except KeyError:
            print(mycolors.foreground.lightred + "\nNo results found for OTX_Query")    
            print(mycolors.reset)
    
class Hashes:
    def vthash(vttext): 
        bkg = 1
        try:
            vttext = vttext["data"]
            timestamp = vttext['attributes']['first_submission_date']
            dt_object = datetime.fromtimestamp(timestamp)        
        except KeyError:
            print(mycolors.foreground.lightred + "\nERROR: Try using VirusTotal_v3_Get_Observable instead!\n")
        
        
            
        try:
            if (bkg == 0):
                print(mycolors.foreground.cyan + "\nFirst Submission Date: ".ljust(13), dt_object + "\n")
            else:
                print(mycolors.foreground.yellow + "\nScan date: ".ljust(13), dt_object)
                print(mycolors.reset)
            
            
            print(mycolors.foreground.lightblue + mycolors.background.lightgrey)            
            #print(mycolors.foreground.lightblue)
            print("\nVIRUSTOTAL SUMMARY")
            print("="*20,'n') 
            print(mycolors.reset)

            if vttext['attributes']['tags']:
                print("Tags:")
                try:
                    for i in range(len(vttext['attributes']['tags'])):
                        print("".ljust(28), end=' ') 
                        print(mycolors.foreground.orange, vttext['attributes']['tags'][i],mycolors.reset)
                except KeyError as e:
                    pass

            if vttext['attributes']['names']:
                print("-"*40)                            
                print("Name(s) of file:")                
                try:
                    for i in range(len(vttext['attributes']['names'])):
                        print("".ljust(28), end=' ') 
                        print(mycolors.foreground.orange, vttext['attributes']['names'][i],mycolors.reset)
                except KeyError as e:
                    pass
            
                    
            print("-"*40)  
            print("\n\n\n")
            print(f"Detection {mycolors.foreground.lightred}{vttext['attributes']['last_analysis_stats']['malicious']}{mycolors.reset}/{mycolors.foreground.lightgreen}60")
            print(mycolors.reset)
            
            if vttext['attributes']['last_analysis_results']:
                for x,y in vttext['attributes']['last_analysis_results'].items():
                    if y['result'] != None:
                        print(f"{mycolors.foreground.lightgreen}{x}:".ljust(20),"=>".ljust(10),f"{mycolors.foreground.lightred}{y['result']}{mycolors.reset}")
            
            print("-"*40)
            print("\n\n")                        
            print(mycolors.foreground.orange + "\nContacted URLs and Domains")
            print("-"*26)
            print(mycolors.reset)
            print(mycolors.foreground.red + "\nContacted URLs " + f"{vttext['relationships']['contacted_urls']['meta']['count']}")
            if vttext['relationships']['contacted_urls']['data']:
                try:
                    for i in range(len(vttext['relationships']['contacted_urls']['data'])):
                        print("".ljust(28), end=' ') 
                        print(mycolors.foreground.orange, vttext['relationships']['contacted_urls']['data'][i]['context_attributes']['url'],mycolors.reset)
                except KeyError as e:
                    pass   
            else:
                print("".ljust(28), end=' ')
                print(mycolors.reset,"NONE")
            
            
            print("-"*40)
            print(mycolors.foreground.red + "\nContacted Domains" + f" {vttext['relationships']['contacted_domains']['meta']['count']}")
            if vttext['relationships']['contacted_domains']['data']:
                try:
                    for i in range(len(vttext['relationships']['contacted_domains']['data'])):
                        print("".ljust(28), end=' ') 
                        print(mycolors.foreground.orange, vttext['relationships']['contacted_domains']['data'][i]['id'])
                except KeyError as e:
                    pass
            else:
                print("".ljust(28), end=' ')
                print(mycolors.reset,"NONE")
                
                
        except ValueError:
            if(bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
        
    def hahash(hatext):
        print(mycolors.foreground.lightred + mycolors.background.lightgrey)
        print("\n\nHYBRIDANALYSIS SUMMARY")
        print("="*24,'n') 
        print(mycolors.reset)            
        try:
            x = 0
            for i in range(len(hatext)): 
                x +=1
                print("".ljust(28), end=' ') 
                print(f"{mycolors.foreground.lightred}Detection {x}")
                print("".ljust(28), end=' ') 
                print("-"*20,mycolors.reset) 
                
                print("FileName   => " + mycolors.foreground.orange +hatext[i]['submit_name'] + mycolors.reset)
                
                if hatext[i]['verdict'] != None:
                    print("Verdict    => " + mycolors.foreground.orange + hatext[i]['verdict'] + mycolors.reset)
                
                if hatext[i]['submissions'] != None:
                    print("Number of submissions    => ", mycolors.foreground.orange, len(hatext[i]['submissions']), mycolors.reset)
                    
                if hatext[i]['type_short'] != None:
                    print("FileType   => " + mycolors.foreground.orange + f"{hatext[i]['type_short']}" + mycolors.reset)  
                
                if hatext[i]['av_detect'] != None:
                    print("AV Detect  => "+ mycolors.foreground.orange, hatext[i]['av_detect'], mycolors.reset)
                    
                if hatext[i]['vx_family'] != None:
                    print("Mal Family => " + mycolors.foreground.orange + hatext[i]['vx_family'] + mycolors.reset)
                
                if hatext[i]['environment_description'] != None:
                    print("Analysis environment => " + mycolors.foreground.orange + hatext[i]['environment_description'] + "\n")
                    
    
        except KeyError as e:
            pass         
        
    def otxhash(otxtext):
        try:
            print(mycolors.foreground.lightblue + mycolors.background.lightgrey)
            print("\nOTXQuery SUMMARY")
            print("-"*20,'n') 
            print(mycolors.reset)            
            print(mycolors.foreground.lightcyan + "General Info: ".ljust(17),mycolors.reset)
            
            # Get General Info
            if (bool(otxtext['pulses'])):
                try:
                    print("-"*40)
                    num = 0
                    for i in range(0, len(otxtext['pulses'])):
                        if (otxtext['pulses'][i].get('name')):
                            num +=1
                            print("".ljust(28), end=' ')
                            print(f"Data {mycolors.foreground.orange}{num}")
                            print("".ljust(28), end=' ')                            
                            print(("Name: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['name'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('tags')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Tags: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['tags'],mycolors.reset)))
                        if (otxtext['pulses'][i].get('targeted_countries')):
                            print("".ljust(28), end=' ')
                            print((mycolors.foreground.orange + "Targeted Countries: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['targeted_countries'],mycolors.reset)))                                
                        if (otxtext['pulses'][i].get('references')):
                            print("".ljust(28), end=' ')
                            print(mycolors.foreground.orange + "References: {0}{1}{2}".format(mycolors.foreground.lightred,otxtext['pulses'][i]['references'],mycolors.reset), end=' ')
                        print("\n")
                except KeyError as e:
                    pass             
            
            #Get yara rule_name(s)
            if otxtext['analysis']['plugins']['yarad']['results']['detection']:
                try:
                    print("Yara rule_name(s) Triggered:")
                    for i in range(len(otxtext['analysis']['plugins'])):
                        print("".ljust(28), end=' ') 
                        print(mycolors.foreground.orange, otxtext['analysis']['plugins']['yarad']['results']['detection'][i]['rule_name'],mycolors.reset)
                except IndexError:
                    pass
                
            
            
            print("-"*40)
            print("\nDetections:\n")
            for x,y in otxtext['analysis']['plugins'].items():
                if 'clamav' in x:
                    print(f"{mycolors.foreground.lightgreen}{x}:".ljust(20),"=>".ljust(10),f"{mycolors.foreground.lightred}{y['results'].get('detection')}{mycolors.reset}")
                elif 'msdefender' in x:
                    print(f"{mycolors.foreground.lightgreen}{x}:".ljust(20),"=>".ljust(10),f"{mycolors.foreground.lightred}{y['results'].get('detection')}{mycolors.reset}")

                     
            for x,y in otxtext['analysis']['plugins'].items():    
                if 'strings' in x:
                    res = input("\nWould you like to see the strings? (y | n): ")
                    with open("strings.txt",'w+') as f:
                        if res.lower() == "y":
                            print(f"{mycolors.foreground.lightgreen}{x}:".ljust(20),"\n")
                            for i in range(0, len(y['results'])): 
                                print(f"{mycolors.foreground.lightgreen}=> "f"{mycolors.foreground.lightred}{y['results'][i]}{mycolors.reset}")
                                f.write(f"{y['results'][i]}\n")
                            print(mycolors.foreground.lightgreen + "\nStrings have been written under {}\\strings.txt".format((os.getcwd())))
                        else:
                            pass
            
                
                
            print("-"*40)
            # Get OTX domain detected malware samples
            print(mycolors.foreground.lightred + "\nDetected malware samples: ".ljust(17))                
            if 'malware_samples' in otxtext:
                if (bool(otxtext['malware_samples'])):
                    try:
                        for i in range(0, len(otxtext['malware_samples'])):
                            if (otxtext['malware_samples'][i]):
                                print("".ljust(28), end=' ')
                                print((f"{otxtext['malware_samples'][i]}"))                    
                    except KeyError as e:
                        pass   
                else:
                    print("".ljust(28), end=' ')
                    print(mycolors.reset,"NONE")
            
            
            print("-"*20)
            # Get OTX domain detected URLs
            print(mycolors.foreground.lightcyan + "\nDetected URLs: ".ljust(17))  
            if 'url_list' in otxtext:
                if (bool(otxtext['url_list'])):
                    try:
                        for i in range(0, len(otxtext['url_list'])):
                            if (otxtext['url_list'][i]).get('url'):
                                print("".ljust(28), end=' ')
                                print(f"{otxtext['url_list'][i]['url']}")                    
                    except KeyError as e:
                        pass  
                else:
                    print("".ljust(28), end=' ')
                    print(mycolors.reset,"NONE")
            
        except ValueError:
            print((mycolors.foreground.red + "Error while connecting to OTX_Query!\n"))
            print(mycolors.reset)
        except (KeyError,TypeError):
            print(mycolors.foreground.lightred + "\nNo results found for OTX_Query")    
            print(mycolors.reset) 
       