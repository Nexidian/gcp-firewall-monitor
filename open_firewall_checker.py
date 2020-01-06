open_firewall_checker.py
#!/usr/bin/env/ python

# This script requires the active session to have the credentials for the target project. 
# The client lib will check the file set on the GOOGLE_APPLICATION_CREDENTIALS env variable.
# This is normally located at ~/.config/gcloud/<some_config_name>.json

# Check my blog for a small write up https://www.nexidian.com/check-for-open-firewall-rules-in-google-cloud-using-python/

# https://github.com/googleapis/google-api-python-client
# pip install --upgrade google-api-python-client
import googleapiclient.discovery
import argparse
import os
import json
import requests


class FirewallChecker(object):
    def __init__(self, flags):
        self.flags = flags
        self.compute = googleapiclient.discovery.build('compute', 'v1')
        self.firewall_rules = self.get_firewall_rules()


    def get_firewall_rules(self):
        try:
            result = self.compute.firewalls().list(project=self.flags.project).execute()
        except googleapiclient.errors.HttpError as e:
            reason = str(e._get_reason).split("\"")[-2]
            print('Error: ' + reason)
            if "permission" in reason:
                print("Looks like there was a permission issue. Please double check GOOGLE_APPLICATION_CREDENTIALS is set in your ENV and that it is pointing to the correct service json")
            exit(-1)
        return result['items'] if 'items' in result else None


    def print_firewall_rules(self):
        firewall_rules = self.get_firewall_rules()
        for rule in firewall_rules:
            print(' - ' + rule['name'])
            print('    - Created: ' + rule['creationTimestamp'])
            print('    - Direction: ' + rule['direction'])
            if 'sourceRanges' in rule:
                print('    - Source ranges: ')
                for ip in rule['sourceRanges']:
                    print('      - ' + ip)


    def check_firewall_rules(self):
        for rule in self.firewall_rules:
            self.check_rule_for_open_access(rule)


    def check_rule_for_open_access(self, rule):
        if 'sourceRanges' in rule:
            for ip in rule['sourceRanges']:
                if ip == '0.0.0.0/0':
                    message = "*{0}* - Rule {1} has open access with 0.0.0.0/0. Please Investigate".format(
                        self.flags.project, rule['name'])
                    print(message)
                    self.notify(message)


    def notify(self, message):
        """
        Push a notification to a service like Slack for example
        """
        pass


def main():
    parser = argparse.ArgumentParser(
        __file__, __doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter, )
    parser.add_argument('--project', required=True,
                        type=str, help="gcp project to lookup")
    parser.add_argument('--list', action='store_true',
                        help="list filewall rules for a project")
    parser.add_argument('--check', action='store_true',
                        help="check filewall rules for issues")

    args = parser.parse_args()

    firewall_checker = FirewallChecker(args)

    if args.list:
        print('Firewall rules  in project %s:' % (args.project))
        firewall_checker.print_firewall_rules()
    if args.check:
        firewall_checker.check_firewall_rules()


if __name__ == '__main__':
    main()