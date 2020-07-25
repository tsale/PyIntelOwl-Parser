import geocoder
from datetime import datetime
import os


class MyColors:
        reset = '\033[0m'
        reverse = '\033[07m'
        bold = '\033[01m'

        class Foreground:
                orange = '\033[33m'
                blue = '\033[34m'
                purple = '\033[35m'
                lightgreen = '\033[92m'
                lightblue = '\033[94m'
                pink = '\033[95m'
                lightcyan = '\033[96m'
                red = '\033[31m'
                green = '\033[32m'
                cyan = '\033[36m'
                lightgrey = '\033[37m'
                darkgrey = '\033[90m'
                lightred = '\033[91m'
                yellow = '\033[93m'

        # noinspection SpellCheckingInspection
        class Background:
                black = '\033[40m'
                blue = '\033[44m'
                cyan = '\033[46m'
                lightgrey = '\033[47m'
                purple = '\033[45m'
                green = '\033[42m'
                orange = '\033[43m'
                red = '\033[41m'


class Checkers:
        def __init__(self, results, value):
                self.results = results
                self.value = value

        def check_domain(self):
                vt = {}
                ha = {}
                otx = {}
                for i in self.results:
                        if 'HybridAnalysis_Get_Observable' in i['name']:
                                ha.update(i)
                        elif 'VirusTotal_v2_Get_Observable' in i['name']:
                                vt.update(i)
                        elif "OTXQuery" in i['name']:
                                otx.update(i)

                if vt:
                        if "VirusTotal_v2" in vt['name']:
                                domains = Domains(vt['report'], self.value)
                                domains.vtdomaincheck()
                else:
                        print(MyColors.Foreground.lightred + "ERROR: Try using VirusTotal_v2 instead!")
                if ha:
                        domains = Domains(ha['report'], self.value)
                        domains.hadomaincheck()
                if otx:
                        domains = Domains(otx['report'], self.value)
                        domains.otxdomaincheck()

        def check_hash(self):
                vt = {}
                ha = {}
                otx = {}
                for i in self.results:
                        if 'HybridAnalysis_Get_Observable' in i['name']:
                                ha.update(i)
                        elif 'VirusTotal_v3_Get_Observable' in i['name']:
                                vt.update(i)
                        elif "OTXQuery" in i['name']:
                                otx.update(i)

                if vt:
                        if "VirusTotal_v3" in vt['name']:
                                hashes = Hashes(vt['report'], self.value)
                                hashes.vthash()
                else:
                        print(MyColors.Foreground.lightred + "ERROR: Try using VirusTotal_v3 instead!")
                if ha:
                        hashes = Hashes(ha['report'], self.value)
                        hashes.hahash()
                if otx:
                        hashes = Hashes(otx['report'], self.value)
                        hashes.otxhash()

        def check_ip(self):
                vt = {}
                ha = {}
                otx = {}
                abusedb = {}
                censys = {}
                greynoise = {}
                for i in self.results:
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
                        ips = IPs(abusedb['report']['data'], self.value)
                        ips.abipdbcheck()
                if censys:
                        ips = IPs(censys['report'], self.value)
                        ips.censysipcheck()
                if greynoise:
                        ips = IPs(greynoise['report'], self.value)
                        ips.gnoiseipcheck()
                if vt:
                        if "VirusTotal_v2" in vt['name']:
                                domains = Domains(vt['report'], self.value)
                                domains.vtdomaincheck()
                else:
                        print(MyColors.Foreground.lightred + "ERROR: Try using VirusTotal_v2 instead!")

                if ha:
                        ips = IPs(ha['report'], self.value)
                        ips.haipcheck()
                if otx:
                        ips = IPs(otx['report'], self.value)
                        ips.otxipcheck()


class Domains:
        def __init__(self, text, value):
                self.text = text
                self.value = value

        def vt_get_undetected_referrer_samples(self):
                if 'undetected_referrer_samples' in self.text:
                        undetected_samples = self.text['undetected_referrer_samples']
                        if undetected_samples:
                                print("-" * 120)
                                print(MyColors.Foreground.lightcyan + "Undetected Referrer Samples: ".ljust(17))
                                try:
                                        for i in range(0, len(undetected_samples)):
                                                if undetected_samples[i].get('date'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Date: {undetected_samples[i]['date']}")
                                                if undetected_samples[i].get('positives'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Positives: {undetected_samples[i]['positives']}")
                                                if undetected_samples[i].get('total'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Total: {undetected_samples[i]['total']}")
                                                if undetected_samples[i].get('sha256'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"SHA256: {undetected_samples[i]['sha256']}", end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

        def vt_get_detected_referrer_samples(self):
                if 'detected_referrer_samples' in self.text:
                        ref_samples = self.text['detected_referrer_samples']
                        if ref_samples:
                                print("-" * 120)
                                print(MyColors.Foreground.pink + "Detected Referrer Samples: ".ljust(17))
                                try:
                                        for i in range(len(ref_samples)):

                                                if ref_samples[i].get('date'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"Date: {ref_samples[i]['date']}")
                                                if ref_samples[i].get('positives'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"Positives: {ref_samples[i]['positives']}")
                                                if ref_samples[i].get('total'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"Total: {ref_samples[i]['total']}")
                                                if ref_samples[i].get('sha256'):
                                                        print("".ljust(28), end=' ')
                                                        print((
                                    f"SHA256: {ref_samples[i]['sha256']}"),
                                  end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

        def vt_get_undetected_downloaded_samples(self):
                if 'undetected_downloaded_samples' in self.text:
                        undetected_samples = self.text['undetected_downloaded_samples']
                        if undetected_samples:
                                print("-" * 120)
                                print(MyColors.Foreground.lightgreen + "\nUndetected Download Samples: ")
                                try:
                                        for i in range(len(undetected_samples)):
                                                if undetected_samples[i].get('date'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Date: {undetected_samples[i]['date']}")
                                                if undetected_samples[i].get('positives'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Positives: {undetected_samples[i]['positives']}")
                                                if undetected_samples[i].get('total'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"Total: {undetected_samples[i]['total']}")
                                                if undetected_samples[i].get('sha256'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"SHA256: {undetected_samples[i]['sha256']}", end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

        def vt_get_detected_samples(self):

                if 'detected_downloaded_samples' in self.text:
                        download_samples = self.text['detected_downloaded_samples']
                        if download_samples:
                                print("-" * 120)
                                print(MyColors.Foreground.orange + "\nDetected Downloaded Samples: ".ljust(
                        17))
                                try:
                                        for i in range(len(download_samples)):
                                                if download_samples[i].get('date'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"Date: {download_samples[i]['date']}")
                                                if (
                                download_samples[i].get('positives')):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"Positives: {download_samples[i]['positives']}")
                                                if download_samples[i].get('total'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"total: {download_samples[i]['total']}")
                                                if download_samples[i].get('sha256'):
                                                        print("".ljust(28), end=' ')
                                                        print(
                                    f"sha256: {download_samples[i]['sha256']}",
                                end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

                if 'detected_communicating_samples' in self.text:
                        print("-" * 120)
                        print(
                    MyColors.Foreground.lightcyan + "\nDetected Communicating Samples: \n".ljust(
                        17))
                        try:
                                samples = self.text['detected_communicating_samples']
                                for i in range(0, len(samples)):
                                        if samples[i].get('date'):
                                                print("".ljust(28), end=' ')
                                                print(f"Date: {samples[i]['date']}")
                                        if samples[i].get('positives'):
                                                print("".ljust(28), end=' ')
                                                print(f"Positives: {samples[i]['positives']}")
                                        if samples[i].get('total'):
                                                print("".ljust(28), end=' ')
                                                print(f"Total: {samples[i]['total']}")
                                        if samples[i].get('sha256'):
                                                print("".ljust(28), end=' ')
                                                print(f"SHA256: {samples[i]['sha256']}", end=' ')
                                        print("\n")
                        except KeyError:
                                pass

        def vt_get_urls(self):

                if 'detected_urls' in self.text:
                        urls = self.text['detected_urls']
                        if urls:
                                print("-" * 120)
                                print(MyColors.Foreground.yellow + "\nDetected URLs: ".ljust(17))
                                try:
                                        for i in range(len(urls)):
                                                if urls[i].get('url'):
                                                        print("".ljust(28), end=' ')
                                                        print(("url: {}".format(
                                    urls[i]['url'])))
                                                if urls[i].get('positives'):
                                                        print("".ljust(28), end=' ')
                                                        print(("{}Positives: {}{}".format(MyColors.reset,
                                                              MyColors.Foreground.lightred,
                                                              self.text[
                                                                      'detected_urls'][i][
                                                                          'positives']) + MyColors.Foreground.yellow))
                                                if urls[i].get('total'):
                                                        print("".ljust(28), end=' ')
                                                        print(("{}Total: {}{}".format(MyColors.reset,
                                                          MyColors.Foreground.lightgreen,
                                                          urls[i][
                                                                  'total']) + MyColors.Foreground.yellow))
                                                if urls[i].get('scan_date'):
                                                        print("".ljust(28), end=' ')
                                                        print("scan_date: {}".format(
                                    urls[i]['scan_date']), end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

                if 'undetected_urls' in self.text:
                        urls = self.text['undetected_urls']
                        if urls:
                                print("-" * 120)
                                print(MyColors.Foreground.lightred + "\nUndetected URLs: ".ljust(17))
                                try:
                                        for i in range(len(urls)):
                                                print((MyColors.Foreground.red + "".ljust(28)), end=' ')
                                                print(("Data {}".format(i)))
                                                for y in range(len(urls[i])):
                                                        print((MyColors.Foreground.lightgreen + "".ljust(28)),
                                  end=' ')
                                                        if y == 0:
                                                                print("url:       ", end=' ')
                                                        if y == 1:
                                                                print("sha256:    ", end=' ')
                                                        if y == 2:
                                                                print("positives: ", end=' ')
                                                        if y == 3:
                                                                print("total:     ", end=' ')
                                                        if y == 4:
                                                                print("date:      ", end=' ')
                                                        print(urls[i][y])
                                                print("\n")
                                except KeyError:
                                        pass

        def vt_get_timestamp(self):

                print("-" * 120)
                print(MyColors.Foreground.yellow + "\nWhois Timestamp: ".ljust(17))
                if 'whois_timestamp' in self.text:
                        try:
                                print("".ljust(28), end=' ')
                                ts = self.text['whois_timestamp']
                                print((datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:{}')))
                        except KeyError:
                                pass

        def vt_get_resolutions(self):

                if 'resolutions' in self.text:
                        print("-" * 120)
                        print(MyColors.Foreground.lightred + "Resolutions: ".ljust(17))
                        try:
                                for i in range(len(self.text['resolutions'])):
                                        resolutions = self.text['resolutions']
                                        if resolutions[i].get('last_resolved'):
                                                print("".ljust(28), end=' ')
                                                print(f"Last resolved: {resolutions[i]['last_resolved']}")
                                        if resolutions[i].get('ip_address'):
                                                print("".ljust(28), end=' ')
                                                print("IP address:   {}".format(resolutions[i]['ip_address']), end=' ')
                                                print("\t" + f"(City:{geocoder.ip(resolutions[i]['ip_address']).city})")
                                        print("\n")
                        except KeyError:
                                pass

        def vt_get_subdomains(self):
                if 'subdomains' in self.text:
                        print("-" * 120)
                        print(MyColors.Foreground.lightgreen + "\nSubdomains: ".ljust(17))
                        try:
                                for i in range(len(self.text['subdomains'])):
                                        print("".ljust(28), end=' ')
                                        print((self.text['subdomains'][i]))
                        except KeyError:
                                pass

        def vt_get_domain_siblings(self):
                if 'domain_siblings' in self.text:
                        if self.text['domain_siblings']:
                                print("-" * 120)
                                print(MyColors.Foreground.lightcyan + "\nDomain Siblings: ".ljust(17))
                                try:
                                        for i in range(len(self.text['domain_siblings'])):
                                                print("".ljust(28), end=' ')
                                                print(self.text['domain_siblings'][i], end=' ')
                                                print("\n")
                                except KeyError:
                                        pass

        def vt_get_categories(self):
                if 'categories' in self.text:
                        print("-" * 120)
                        print(MyColors.Foreground.lightcyan + "\nCategories: ".ljust(17))
                        try:
                                for i in range(len(self.text['categories'])):
                                        print("".ljust(28), end=' ')
                                        print((self.text['categories'][i]))
                        except KeyError:
                                pass

        def ha_get_results(self):
                try:
                        if 'result' in self.text:
                                results = self.text['result']
                                if results:
                                        print(MyColors.Foreground.orange + "\nResults found: {}".format(self.text["count"]))
                                        print("-" * 28)
                                        for i in range(len(results)):
                                                if results[i]['verdict'] is not None:
                                                        print(MyColors.Foreground.orange, "Verdict\t=> ", MyColors.Foreground.lightred,
                                  results[i]['verdict'])
                                                if results[i]['sha256']:
                                                        print(MyColors.Foreground.orange, "SHA256\t=> ", MyColors.Foreground.lightred,
                                  results[i]['sha256'])
                                                if results[i]['av_detect'] is not None:
                                                        print(MyColors.Foreground.orange, "AV Detect\t=> ", MyColors.Foreground.lightred,
                                  results[i]['av_detect'])
                                                if results[i]['vx_family'] is not None:
                                                        print(MyColors.Foreground.orange, "Mal Family\t=> ", MyColors.Foreground.lightred,
                                  results[i]['vx_family'])
                                                if results[i]['submit_name'] is not None:
                                                        print(MyColors.Foreground.orange, "FileName\t=> ", MyColors.Foreground.lightred,
                                  results[i]['submit_name'])
                                                if results[i]['type_short'] is not None:
                                                        print(MyColors.Foreground.orange,
                                  "FileType\t=> ", MyColors.Foreground.lightred,
                                  results[i]['type_short'] + "\n")
                                else:
                                        print(MyColors.Foreground.lightred + "\nNo results found for HYBRIDANALYSIS")

                except KeyError:
                        pass

        def otx_get_general_info(self):
                # Get General Info
                if 'pulses' in self.text['pulses']:
                        pulses = self.text['pulses']
                        try:
                                print("-" * 120)
                                num = 0
                                for i in range(0, len(pulses)):
                                        if pulses[i].get('name'):
                                                num += 1
                                                print("".ljust(28), end=' ')
                                                print(f"Data {MyColors.Foreground.orange}{num}")
                                                print("".ljust(28), end=' ')
                                                print(("Name: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                        pulses[i]['name'], MyColors.reset)))
                                        if pulses[i].get('tags'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Tags: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                                                     pulses[i]['tags'],
                                                                                     MyColors.reset)))
                                        if pulses[i].get('targeted_countries'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Targeted Countries: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['targeted_countries'],
                            MyColors.reset)))
                                        if pulses[i].get('references'):
                                                print("".ljust(28), end=' ')
                                                print(MyColors.Foreground.orange + "References: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['references'], MyColors.reset),
                              end=' ')
                                        print("\n")
                        except KeyError:
                                pass

        def otx_get_detected_samples(self):

                # Get OTX domain detected malware samples
                if 'malware_samples' in self.text:
                        samples = self.text['malware_samples']
                        if samples:
                                print("-" * 120)
                                print(MyColors.Foreground.lightred + "\nDetected malware samples: ".ljust(17))
                                try:
                                        for i in range(0, len(samples)):
                                                if samples[i]:
                                                        print("".ljust(28), end=' ')
                                                        print(samples[i])
                                except KeyError:
                                        pass
                else:
                        print("".ljust(28), end=' ')
                        print(MyColors.reset, "NONE")

        def otx_get_detected_urls(self):
                # Get OTX domain detected URLs
                if 'url_list' in self.text:
                        url_list = self.text['url_list']
                        if url_list:
                                print("-" * 120)
                                print(MyColors.Foreground.lightcyan + "\nDetected URLs: ".ljust(17))
                                try:
                                        for i in range(0, len(url_list)):
                                                if (url_list[i]).get('url'):
                                                        print("".ljust(28), end=' ')
                                                        print(url_list[i]['url'])
                                except KeyError:
                                        pass
                        else:
                                print("".ljust(28), end=' ')
                                print(MyColors.reset, "NONE")

        def vtdomaincheck(self):
                try:
                        print(MyColors.reset)
                        print("\n\tDOMAIN SUMMARY REPORT")
                        print("-" * 35, "\n")
                        print(MyColors.Foreground.lightblue, MyColors.Background.lightgrey)
                        print("\nVIRUSTOTAL SUMMARY")
                        print("=" * 25)
                        print(MyColors.reset)

                        self.vt_get_timestamp()
                        self.vt_get_resolutions()
                        self.vt_get_subdomains()
                        self.vt_get_domain_siblings()
                        self.vt_get_undetected_referrer_samples()
                        self.vt_get_detected_referrer_samples()
                        self.vt_get_undetected_downloaded_samples()
                        self.vt_get_detected_samples()
                        self.vt_get_urls()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to Virus Total!\n"))
                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "No results found in VirusTotal!\n")

        def hadomaincheck(self):
                try:
                        print(MyColors.Foreground.lightred, MyColors.Background.lightgrey)
                        print("\nHYBRIDANALYSIS SUMMARY")
                        print("=" * 25, "\n", MyColors.reset)

                        self.ha_get_results()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to HybridAnalysis!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for HybridAnalysis")

        def otxdomaincheck(self):
                try:
                        print(MyColors.Foreground.lightblue + MyColors.Background.cyan)
                        print("\nOTXQuery SUMMARY")
                        print("=" * 25, '\n', MyColors.reset)

                        self.otx_get_general_info()
                        self.otx_get_detected_samples()
                        self.otx_get_detected_urls()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to OTX_Query!\n"))
                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "\nNo results found for OTX_Query")


class IPs:
        def __init__(self, text, value):
                self.text = text
                self.value = value

        def abip_get_info(self):

                print(MyColors.Foreground.lightcyan)
                if self.text['isp'] is not None:
                        print("".ljust(28), end=' ')
                        print("ISP: {}".format((self.text['isp'])))
                if self.text['domain'] is not None:
                        print("".ljust(28), end=' ')
                        print("Domain: =>\t{}".format((self.text['domain'])))
                if self.text['usageType'] is not None:
                        print("".ljust(28), end=' ')
                        print("IP usage_type: =>\t{}".format((self.text['usageType'])))
                if self.text['countryName'] is not None:
                        print("".ljust(28), end=' ')
                        print("Country Name: =>\t{}".format((self.text['countryName'])))

        def gnoise_get_ip_info(self):

                print(MyColors.Foreground.orange + "\nResults found: {}".format((self.text['returned_count'])))
                print("-" * 28)

                print(MyColors.Foreground.lightgrey)
                if 'records' in self.text:
                        records = self.text['records']
                        try:
                                for i in range(len(records)):
                                        if records[i]['name'] is not None:
                                                print("\nRecord:\t=>\t{}".format((records[i]['name'])))
                                        if records[i]['metadata'] is not None:
                                                print("".ljust(20), end=' ')
                                                print("Tor:\t=>\t{}".format((records[i]['metadata']['tor'])))
                                        if records[i]['confidence'] is not None:
                                                print("".ljust(20), end=' ')
                                                print("Confidence:\t=>\t{}".format((records[i]['confidence'])))
                                        if records[i]['last_updated'] is not None:
                                                print("".ljust(20), end=' ')
                                                print("Last_updated:\t=>\t{}".format((records[i]['last_updated'])))
                        except KeyError:
                                pass

        def censys_get_running_services(self):
                for i in self.text['protocols']:
                        print(MyColors.Foreground.yellow)
                        print("Services running: ")
                        print("".ljust(28), end=' ')
                        print(i)

                print("\nLast updated: {}".format((self.text['updated_at'])))
                print("-" * 120)

        def ha_get_ip_info(self):
                try:
                        if 'result' in self.text:
                                results = self.text['result']
                                if results:
                                        print(MyColors.Foreground.orange + "\nResults found: {}".format(self.text["count"]))
                                        print("-" * 28)
                                        for i in range(len(results)):
                                                if results[i]['verdict'] is not None:
                                                        print(MyColors.Foreground.orange, "Verdict\t=> ", MyColors.Foreground.lightred,
                                  results[i]['verdict'])
                                                if results[i]['sha256']:
                                                        print(MyColors.Foreground.orange, "SHA256\t=> ", MyColors.Foreground.lightred,
                                  results[i]['sha256'])
                                                if results[i]['av_detect'] is not None:
                                                        print(MyColors.Foreground.orange, "AV Detect\t=> ", MyColors.Foreground.lightred,
                                  results[i]['av_detect'])
                                                if results[i]['vx_family'] is not None:
                                                        print(MyColors.Foreground.orange, "Mal Family\t=> ", MyColors.Foreground.lightred,
                                  results[i]['vx_family'])
                                                if results[i]['submit_name'] is not None:
                                                        print(MyColors.Foreground.orange, "FileName\t=> ", MyColors.Foreground.lightred,
                                  results[i]['submit_name'])
                                                if results[i]['type_short'] is not None:
                                                        print(MyColors.Foreground.orange,
                                  "FileType\t=> ", MyColors.Foreground.lightred,
                                  results[i]['type_short'] + "\n")
                                else:
                                        print(MyColors.Foreground.lightred + "\nNo results found for HYBRIDANALYSIS")

                except KeyError:
                        pass

        def otx_get_ip_info(self):
                # Get General Info
                if 'pulses' in self.text:
                        pulses = self.text['pulses']
                        try:
                                print("-" * 120)
                                num = 0
                                for i in range(0, len(pulses)):
                                        if pulses[i].get('name'):
                                                num += 1
                                                print("".ljust(28), end=' ')
                                                print(f"Data {MyColors.Foreground.orange}{num}")
                                                print("".ljust(28), end=' ')
                                                print(("Name: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                        pulses[i]['name'], MyColors.reset)))
                                        if pulses[i].get('tags'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Tags: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                                                     pulses[i]['tags'],
                                                                                     MyColors.reset)))
                                        if pulses[i].get('targeted_countries'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Targeted Countries: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['targeted_countries'],
                            MyColors.reset)))
                                        if pulses[i].get('references'):
                                                print("".ljust(28), end=' ')
                                                print(MyColors.Foreground.orange + "References: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['references'], MyColors.reset),
                              end=' ')
                                        print("\n")
                        except KeyError:
                                pass

        def otx_get_malware_samples(self):
                print("-" * 120)
                # Get OTX IP detected malware samples
                print(MyColors.Foreground.lightred + "\nDetected malware samples: ".ljust(17))
                if 'malware_samples' in self.text:
                        samples = self.text['malware_samples']
                        try:
                                for i in range(0, len(samples)):
                                        if samples[i]:
                                                print("".ljust(28), end=' ')
                                                print(("{}".format(samples[i])))
                        except KeyError:
                                pass
                else:
                        print("".ljust(28), end=' ')
                        print(MyColors.reset, "NONE")

        def otx_get_detected_urls(self):
                # Get OTX IP detected URLs
                if 'url_list' in self.text:
                        urls = self.text['url_list']
                        if urls:
                                print("-" * 120)
                                print(MyColors.Foreground.lightcyan + "\nDetected URLs: ".ljust(17))
                                try:
                                        for i in range(0, len(urls)):
                                                if (urls[i]).get('url'):
                                                        print("".ljust(28), end=' ')
                                                        print(("{}".format(urls[i]['url'])))
                                except KeyError:
                                        pass
                        else:
                                print("".ljust(28), end=' ')
                                print(MyColors.reset, "NONE")

        def abipdbcheck(self):
                try:
                        print(MyColors.Foreground.lightgreen, MyColors.Background.lightgrey)
                        print("\nABUSEIPDB SUMMARY")
                        print("=" * 25, "\n", MyColors.reset)

                        self.abip_get_info()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to AbuseIPDB!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for AbuseIPDB")

        def gnoiseipcheck(self):
                try:
                        print(MyColors.Foreground.lightblue, MyColors.Background.lightgrey)
                        print("\nGREY_NOISE SUMMARY")
                        print("=" * 25, "\n", MyColors.reset)

                        self.gnoise_get_ip_info()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to GreyNoise!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for GreyNoise")

        def censysipcheck(self):
                try:
                        print(MyColors.reset)
                        print("".ljust(20), end=' ')
                        print("\n\nIP ADDRESS SUMMARY REPORT")
                        print("-" * 35, "\n\n")

                        print(MyColors.Foreground.lightred, MyColors.Background.lightgrey)
                        print("\nCENSYS_IP SUMMARY")
                        print("=" * 25, "\n", MyColors.reset)

                        self.censys_get_running_services()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to Cencys!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for Cencys")

        def vtipcheck(self):
                try:
                        print(MyColors.reset)
                        print("".ljust(20), end=' ')
                        print("\n\nIP ADDRESS SUMMARY REPORT")
                        print("-" * 35, "\n\n", MyColors.reset)

                        if 'resolutions' in self.text:
                                print(MyColors.Foreground.yellow + "\nResolutions")
                                print("-" * 11)
                                print(MyColors.reset)
                                num = 0
                                if self.text['resolutions']:
                                        for i in self.text['resolutions']:
                                                if num >= 6:
                                                        url = f"https://www.virustotal.com/gui/ip-address/{self.value}/relations"
                                                        print(MyColors.Foreground.lightgreen + "\n......", MyColors.reset)
                                                        print(
                                    MyColors.Foreground.green + f'\nToo many resolutions... Check in browser: {url} ')
                                                        print(MyColors.reset)
                                                        break
                                                else:
                                                        print(MyColors.Foreground.lightgreen + "\nLast Resolved:\t" + i[
                                    'last_resolved'], MyColors.reset)
                                                        print(MyColors.Foreground.lightgreen + "Hostname:\t" + i['hostname'], MyColors.reset)
                                                        num += 1

                        if 'detected_urls' in self.text:
                                print(MyColors.reset + "\nDetected URLs")
                                print("-" * 13)
                                num = 0
                                for j in self.text['detected_urls']:
                                        if num >= 6:
                                                url = f"https://www.virustotal.com/gui/ip-address/{self.value}/relations"
                                                print(MyColors.Foreground.lightred + "\n......", MyColors.reset)
                                                print(
                                MyColors.Foreground.green + f"\n*** Too many Detected URLs... Check in browser: {url}")
                                                print(MyColors.reset)
                                                break
                                        else:
                                                print(MyColors.Foreground.lightred + "\nURL:\t\t{}".format(j['url']), MyColors.reset)
                                                print(MyColors.Foreground.lightred + "Scan date:\t{}".format(j['scan_date']), MyColors.reset)
                                                print(MyColors.Foreground.lightred + "Positives:\t{}".format(j['positives']), MyColors.reset)
                                                print(MyColors.Foreground.lightred + "Total:\t\t{}".format(j['total']), MyColors.reset)
                                                num += 1

                        if 'detected_downloaded_samples' in self.text:
                                print(MyColors.reset + "\nDetected Downloaded Samples")
                                print("-" * 27)
                                num = 0
                                for k in self.text['detected_downloaded_samples']:
                                        if num >= 6:
                                                url = f"https://www.virustotal.com/gui/ip-address/{self.value}/relations"
                                                print(MyColors.Foreground.lightred + "\n......", MyColors.reset)
                                                print(
                                MyColors.Foreground.green + f"\n*** Too many Detected URLs... Check in browser: {url}")
                                                print(MyColors.reset)
                                                break
                                        else:
                                                print(MyColors.Foreground.yellow + "\nSHA256:\t\t{}".format(k['sha256']), MyColors.reset)
                                                print(MyColors.Foreground.yellow + "Date:\t\t{}".format(k['date']), MyColors.reset)
                                                print(MyColors.Foreground.yellow + "Positives:\t{}".format(k['positives']), MyColors.reset)
                                                print(MyColors.Foreground.yellow + "Total:\t\t{}".format(k['total']), MyColors.reset)
                                                num += 1

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to VirusTotal!\n"))
                        print(MyColors.reset)
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for VirusTotal")
                        print(MyColors.reset)

        def haipcheck(self):
                try:
                        print(MyColors.Foreground.lightred, MyColors.Background.lightgrey)
                        print("\nHYBRIDANALYSIS SUMMARY")
                        print("=" * 25, "\n", MyColors.reset)

                        self.ha_get_ip_info()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to HybridAnalysis!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for HYBRIDANALYSIS")

        def otxipcheck(self):
                try:
                        print(MyColors.Foreground.lightblue + MyColors.Background.lightgrey)
                        print("\nOTXQuery SUMMARY")
                        print("=" * 25, '\n', MyColors.reset)
                        print(MyColors.Foreground.lightcyan + "General Info: ".ljust(17))

                        self.otx_get_ip_info()
                        self.otx_get_malware_samples()
                        self.otx_get_detected_urls()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to OTX_Query!\n"))
                except KeyError:
                        print(MyColors.Foreground.lightred + "\nNo results found for OTX_Query")


class Hashes:
        def __init__(self, text, value):
                self.text = text
                self.value = value

        def vt_get_scan_date(self):
                self.text = self.text["data"]
                timestamp = self.text['attributes']['first_submission_date']
                dt_object = datetime.fromtimestamp(timestamp)

                print(MyColors.Foreground.yellow + "\nScan date: ".ljust(13), dt_object)

        def vt_get_general_info(self):

                try:
                        if bool(self.text['attributes']['tags']):
                                tags = self.text['attributes']['tags']
                                print("Tags:")
                                for i in range(len(tags)):
                                        print("".ljust(28), end=' ')
                                        print(MyColors.Foreground.orange, tags[i], MyColors.reset)
                        if bool(self.text['attributes']['names']):
                                names = self.text['attributes']['names']
                                print("-" * 120)
                                print("Name(s) of file:")
                                for i in range(len(names)):
                                        print("".ljust(28), end=' ')
                                        print(MyColors.Foreground.orange, names[i], MyColors.reset)
                except KeyError:
                        pass

        def vt_get_analysis_results(self):

                print("-" * 120)
                print("\n\n\n")
                ct_malicious = MyColors.Foreground.lightred + str(self.text['attributes']['last_analysis_stats']['malicious'])
                ct_sources = MyColors.Foreground.lightgreen + '60'
                print(f"Detection {ct_malicious}{MyColors.reset}/{ct_sources}")
                print(MyColors.reset)

                if self.text['attributes']['last_analysis_results']:
                        analysis = self.text['attributes']['last_analysis_results']
                        for x, y in analysis.items():
                                if y['result'] is not None:
                                        print(f"{MyColors.Foreground.lightgreen}{x}:".ljust(20), "=>".ljust(10),
                          f"{MyColors.Foreground.lightred}{y['result']}{MyColors.reset}")

        def vt_get_domains(self):

                print("-" * 120)
                print("\n\n")
                print(MyColors.Foreground.orange + "\nContacted URLs")
                print("-" * 26)
                ct_urls = self.text['relationships']['contacted_urls']['meta']['count']
                print(
                MyColors.Foreground.red + "\nContacted URLs {}".format(ct_urls))
                if bool(self.text['relationships']['contacted_urls']['data']):
                        data = self.text['relationships']['contacted_urls']['data']
                        try:
                                for i in range(len(data)):
                                        print("".ljust(28), end=' ')
                                        print(MyColors.Foreground.orange,
                          data[i]['context_attributes']['url'],
                          MyColors.reset)
                        except KeyError:
                                pass
                else:
                        print("".ljust(28), end=' ')
                        print(MyColors.reset, "NONE")

        def vt_get_urls(self):

                print("-" * 120)
                ct_domains = self.text['relationships']['contacted_domains']['meta']['count']
                print(
                MyColors.Foreground.red + "\nContacted Domains {}".format(ct_domains))
                if bool(self.text['relationships']['contacted_domains']['data']):
                        data = self.text['relationships']['contacted_domains']['data']
                        try:
                                for i in range(len(data)):
                                        print("".ljust(28), end=' ')
                                        print(MyColors.Foreground.orange,
                          data[i]['id'])
                        except KeyError:
                                pass
                else:
                        print("".ljust(28), end=' ')
                        print(MyColors.reset, "NONE")

        def ha_get_info(self):

                try:
                        x = 0
                        if self.text:
                                for i in range(len(self.text)):
                                        x += 1
                                        print("".ljust(28), end=' ')
                                        print(f"{MyColors.Foreground.lightred}Detection {x}")
                                        print("".ljust(28), end=' ')
                                        print("-" * 20, MyColors.reset)

                                        print("FileName\t=> " + MyColors.Foreground.orange + self.text[i]['submit_name'], MyColors.reset)

                                        if self.text[i]['verdict'] is not None:
                                                print("Verdict\t=> " + MyColors.Foreground.orange + self.text[i]['verdict'], MyColors.reset)

                                        if self.text[i]['submissions'] is not None:
                                                print("Number of submissions\t=> ", MyColors.Foreground.orange,
                              len(self.text[i]['submissions']),
                              MyColors.reset)

                                        if self.text[i]['type_short'] is not None:
                                                print(
                                "FileType\t=> " + MyColors.Foreground.orange + f"{self.text[i]['type_short']}",
                            MyColors.reset)

                                        if self.text[i]['av_detect'] is not None:
                                                print("AV Detect\t=> " + MyColors.Foreground.orange, self.text[i]['av_detect'], MyColors.reset)

                                        if self.text[i]['vx_family'] is not None:
                                                print("Mal Family\t=> " + MyColors.Foreground.orange + self.text[i]['vx_family'],
                              MyColors.reset)

                                        if self.text[i]['environment_description'] is not None:
                                                print("Analysis environment\t=> " + MyColors.Foreground.orange + self.text[i][
                                'environment_description'] + "\n")
                        else:
                                print(MyColors.Foreground.lightred + "No results found in HybridAnalysis!\n")

                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "No results found in HybridAnalysis!\n")

        def otx_get_general_info(self):
                # Get General Info
                if bool(self.text['pulses']):
                        pulses = self.text['pulses']
                        try:
                                num = 0
                                for i in range(0, len(pulses)):
                                        if pulses[i].get('name'):
                                                num += 1
                                                print("".ljust(28), end=' ')
                                                print(f"Data {MyColors.Foreground.orange}{num}")
                                                print("".ljust(28), end=' ')
                                                print(("Name: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                        pulses[i]['name'], MyColors.reset)))
                                        if pulses[i].get('tags'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Tags: {0}{1}{2}".format(MyColors.Foreground.lightred,
                                                                                     pulses[i]['tags'],
                                                                                     MyColors.reset)))
                                        if pulses[i].get('targeted_countries'):
                                                print("".ljust(28), end=' ')
                                                print((MyColors.Foreground.orange + "Targeted Countries: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['targeted_countries'],
                            MyColors.reset)))
                                        if pulses[i].get('references'):
                                                print("".ljust(28), end=' ')
                                                print(MyColors.Foreground.orange + "References: {0}{1}{2}".format(
                                MyColors.Foreground.lightred, pulses[i]['references'], MyColors.reset),
                              end=' ')
                                        print("\n")
                        except KeyError:
                                pass

        def otx_get_yara(self):
                # Get yara rule_name(s)
                if bool(self.text['analysis']['plugins']['yarad']['results']['detection']):
                        detection = self.text['analysis']['plugins']['yarad']['results']['detection']
                        try:
                                print("Yara rule_name(s) Triggered:")
                                for i in range(len(self.text['analysis']['plugins'])):
                                        print("".ljust(28), end=' ')
                                        print(MyColors.Foreground.orange,
                          detection[i]['rule_name'],
                          MyColors.reset)
                        except IndexError:
                                pass

        def otx_get_detections(self):

                print("-" * 120)
                print("\nDetections:\n")
                if bool(self.text['analysis']['plugins']):
                        plugins = self.text['analysis']['plugins']
                        for x, y in plugins.items():
                                if 'clamav' in x:
                                        print(f"{MyColors.Foreground.lightgreen}{x}:".ljust(20), "=>".ljust(10),
                          f"{MyColors.Foreground.lightred}{y['results'].get('detection')}{MyColors.reset}")
                                elif 'msdefender' in x:
                                        print(f"{MyColors.Foreground.lightgreen}{x}:".ljust(20), "=>".ljust(10),
                          f"{MyColors.Foreground.lightred}{y['results'].get('detection')}{MyColors.reset}")

        def otx_get_strings(self):

                for x, y in self.text['analysis']['plugins'].items():
                        if 'strings' in x:
                                res = input("\nWould you like to see the strings? (y | n): ")
                                with open("strings.txt", 'w+') as f:
                                        if res.lower() == "y":
                                                print(f"{MyColors.Foreground.lightgreen}{x}:".ljust(20), "\n")
                                                for i in range(0, len(y['results'])):
                                                        results = y['results'][i]
                                                        print(
                                    f"{MyColors.Foreground.lightgreen}=> {MyColors.Foreground.lightred}{results}")
                                                        f.write(f"{results}\n")
                                                print(
                                MyColors.Foreground.lightgreen + "\nStrings written under {}\\strings.txt".format(
                                    (os.getcwd())))

        def otx_get_samples(self):

                print("-" * 120)
                # Get OTX domain detected malware samples
                print(MyColors.Foreground.lightred + "\nDetected malware samples: ".ljust(17))
                if 'malware_samples' in self.text:
                        if bool(self.text['malware_samples']):
                                samples = self.text['malware_samples']
                                try:
                                        for i in range(0, len(samples)):
                                                if samples[i]:
                                                        print("".ljust(28), end=' ')
                                                        print(f"{samples[i]}")
                                except KeyError:
                                        pass
                        else:
                                print("".ljust(28), end=' ')
                                print(MyColors.reset, "NONE")

        def otx_get_urls(self):

                print("-" * 120)
                # Get OTX domain detected URLs
                print(MyColors.Foreground.lightcyan + "\nDetected URLs: ".ljust(17))
                if 'url_list' in self.text:
                        if bool(self.text['url_list']):
                                urls = self.text['url_list']
                                try:
                                        for i in range(0, len(urls)):
                                                if (urls[i]).get('url'):
                                                        print("".ljust(28), end=' ')
                                                        print(f"{urls[i]['url']}")
                                except KeyError:
                                        pass
                        else:
                                print("".ljust(28), end=' ')
                                print(MyColors.reset, "NONE")

        def vthash(self):
                try:
                        print(MyColors.Foreground.lightblue + MyColors.Background.lightgrey)
                        print("\nVIRUSTOTAL SUMMARY")
                        print("=" * 25, '\n', MyColors.reset)

                        self.vt_get_scan_date()
                        self.vt_get_general_info()
                        self.vt_get_analysis_results()
                        self.vt_get_domains()
                        self.vt_get_urls()

                except ValueError:
                        print(MyColors.Foreground.lightred + "Error while connecting to VirusTotal!\n")
                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "No results found in VirusTotal!\n")

        def hahash(self):
                try:
                        print(MyColors.Foreground.lightred + MyColors.Background.lightgrey)
                        print("\n\nHYBRIDANALYSIS SUMMARY")
                        print("=" * 25, '\n', MyColors.reset)

                        self.ha_get_info()

                except ValueError:
                        print(MyColors.Foreground.lightred + "Error while connecting to HybridAnalysis!\n")
                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "No results found in HybridAnalysis!\n")

        def otxhash(self):
                try:
                        print(MyColors.Foreground.lightblue + MyColors.Background.lightgrey)
                        print("\nOTXQuery SUMMARY")
                        print("=" * 25, '\n', MyColors.reset)
                        print(MyColors.Foreground.lightcyan + "General Info: ".ljust(17), MyColors.reset)

                        self.otx_get_general_info()
                        self.otx_get_yara()
                        self.otx_get_detections()
                        self.otx_get_strings()
                        self.otx_get_samples()
                        self.otx_get_urls()

                except ValueError:
                        print((MyColors.Foreground.red + "Error while connecting to OTX_Query!\n"))
                except (KeyError, TypeError):
                        print(MyColors.Foreground.lightred + "\nNo results found for OTX_Query")
