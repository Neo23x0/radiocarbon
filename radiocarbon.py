# -*- coding: utf-8 -*-
#
# Credential Leak Analyzer
# Florian Roth
# November 2017
#
# Determines approximate
# - age of a leak
# - leak source
# - impacted region

__version__ = "0.2"

import os
import argparse
import re
from collections import Counter
from tabulate import tabulate
import colorama

WORD_BLACKLIST = ['gmail', 'hotmail', 'msn', 'mail', 'gmx', 'yahoo', 'arcor', 'freenet', '123456',
                  'password', 'online']
YEAR_BLACKLIST = ['01', '33', '44', '55', '66', '77', '88', '99']
ONE_TIME_INDICATORS = ['mailinator', 'guerrillamail', 'maildrop', 'temp-mail', 'dropmail', 'minutemail',
                       'getnada', 'trashmail', 'yopmail', 'emailsensai']

class RadioCarbon():
    """
    Holds the evaluated data and counters
    """
    number_stats = Counter()
    tld_stats = Counter()
    word_stats = Counter()
    discard_mails = Counter()
    mail_domains = Counter()
    one_time_mails = {}
    plus_mails = {}

    passwords = []

    re_words = re.compile('[\w+]{3,}')
    re_years = re.compile('[^0-9]([0-9]{2}|20[0-9]{2})[^0-9]')
    re_tlds = re.compile('\.[a-z]{2,4}')
    re_mail_domains = re.compile('@([a-zA-Z0-9_\-]+)\.[a-zA-Z]{2,5}')
    re_one_time_mail = re.compile('(([a-zA-Z0-9_\-\.]+)@(%s)\.[a-zA-Z]{2,5})' % "|".join(ONE_TIME_INDICATORS))
    re_plus_mail = re.compile('(([a-zA-Z0-9_\-\.]+)\+([a-zA-Z0-9_\-\.]+)@[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,5})')

    def __init__(self):
        self.readPasswordLists()

    def readPasswordLists(self):
        """
        Read passwords from all files in the given directory
        :return:
        """
        for file in os.listdir("./passlists"):
            if file.endswith(".txt"):
                passFile = os.path.join("./passlists", file)
                with open(passFile, 'r') as fh:
                    self.passwords += fh.read().splitlines()

    def processFile(self, filePath):
        """
        Process a given file with leaked data
        :param filePath:
        :return:
        """
        content = ""
        print("Analyzing {0} ...".format(filePath))
        with open(filePath, 'r') as fh:
            content = fh.read()

        self.word_stats += Counter(self.re_words.findall(content))
        self.number_stats += Counter(self.re_years.findall(content))
        self.tld_stats += Counter(self.re_tlds.findall(content))
        self.mail_domains += Counter(self.re_mail_domains.findall(content))
        self.one_time_mails = self.re_one_time_mail.findall(content)
        self.plus_mails = self.re_plus_mail.findall(content)
        return

    def cleanStats(self):
        """
        Clean stats from blacklisted elements
        :return:
        """
        print("Cleaning the collected statistics ...")
        # Word cleaner
        print("Cleaning the list of words ...")
        for w in list(self.word_stats):
            # Blacklist
            for b in WORD_BLACKLIST:
                if b in w.lower():
                    del self.word_stats[w]
        # TLDs
        print("Removing TLDs from words ...")
        for tld in list(self.tld_stats):
            tld_lower = tld[1:].lower()
            tld_upper = tld[1:].upper()
            if tld_lower in self.word_stats:
                del self.word_stats[tld_lower]
            if tld_upper in self.word_stats:
                del self.word_stats[tld_upper]
        # Mail Domains
        print("Removing mail domains from words ...")
        for dom in list(self.mail_domains):
            dom_lower = dom.lower()
            dom_upper = dom.upper()
            if dom_lower in self.word_stats:
                del self.word_stats[dom_lower]
            if dom_upper in self.word_stats:
                del self.word_stats[dom_upper]
        # Numbers - extend years
        print("Extending numbers in years")
        for num in list(self.number_stats):
            if num in YEAR_BLACKLIST:
                del self.number_stats[num]
                continue
            if len(num) == 2:
                newNum = "(20){0}".format(num)
                oldCount = self.number_stats[num]
                self.number_stats += Counter({newNum: oldCount})
                del self.number_stats[num]
        # Removing typical passwords from pass lists
        print("Removing typical passwords")
        for p in self.passwords:
            p_lower = p.lower()
            p_upper = p.upper()
            if p_lower in self.word_stats:
                del self.word_stats[p_lower]
            if p_upper in self.word_stats:
                del self.word_stats[p_upper]
            # One time mail filtering
            for c, one_time_mail in enumerate(list(self.one_time_mails)):
                if one_time_mail[1] == p_lower or one_time_mail[1] == p_upper:
                    del self.one_time_mails[c]

    def analyzeStats(self):
        """
        Analyze the collected statistics
        :return:
        """
        print("Printing the statistic tables")
        # Date Determination
        print("\nYear:\n" \
              "- Numbers used in passwords often indicate the year in which the password was chosen\n")
        print(tabulate(self.number_stats.most_common(10), headers=["Year", "Count"]))
        # TLD Determination
        print("\nRegion:\n" \
              "- TLD of included email addresses often point to a certain region\n")
        print(tabulate(self.tld_stats.most_common(10), headers=["TLD", "Count"]))
        # Origin Determination
        print("\nOrigin:\n" \
              "- strings used in passwords often point to a certain origin\n")
        print(tabulate(self.word_stats.most_common(30), headers=["Word", "Count"]))
        # Trash Mail Listing
        print("\nOne Time Emails:\n" \
              "- Sometimes the one time email addresses used for services include the service name\n")
        print(tabulate(self.one_time_mails, headers=["Mail", "User", "Provider"]))
        # Plus Character Mail Listing
        print("\nEmails with Plus (+) Character:\n" \
              "- You can add a '+' symbol to email addresses - those often include the service name\n")
        print(tabulate(self.plus_mails, headers=["Mail", "User", "Provider"]))

def printWelcome():
    """
    Print the welcome message
    :return:
    """
    print(" ")
    print("    ___          ___      _____         __            ")
    print("   / _ \___ ____/ (_)__  / ___/__ _____/ /  ___  ___  ")
    print("  / , _/ _ `/ _  / / _ \/ /__/ _ `/ __/ _ \/ _ \/ _ \ ")
    print(" /_/|_|\_,_/\_,_/_/\___/\___/\_,_/_/ /_.__/\___/_//_/ ")
    print("                                                      ")
    print(" Florian Roth, November 2017")
    print(" Version {0}".format(__version__))
    print(" ")

# MAIN ################################################################
if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='RadioCarbon - Credential Leak Analyzer')
    parser.add_argument('-f', help='File to analyze', metavar='leak-file', default='')
    args = parser.parse_args()

    printWelcome()

    rc = RadioCarbon()

    rc.processFile(args.f)
    rc.cleanStats()
    rc.analyzeStats()
