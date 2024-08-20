import time
from scapy import all as scapy
from scapy.layers.inet import IP
# Placeholder functions for feature extraction
def calculate_vowel_consonant_ratio(domain_name):
    vowels = ['a', 'e', 'i', 'o', 'u']
    consonants = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z']
    
    vowel_count = 0
    consonant_count = 0

    for char in domain_name:
        if char.lower() in vowels:
            vowel_count += 1
        elif char.lower() in consonants:
            consonant_count += 1
    
    if consonant_count == 0:
        return float('inf')
    
    vowel_consonant_ratio = vowel_count / consonant_count
    return vowel_consonant_ratio

def calculate_number_character_ratio(domain_name):
    number_count = sum(char.isdigit() for char in domain_name)
    character_count = len(domain_name)
    
    if character_count == 0:
        return 0
    
    number_character_ratio = number_count / character_count
    return number_character_ratio


def calculate_arrival_time(stream):
    # my implementation
    arrival_time = stream[0].time
    return arrival_time
    pass

def calculate_packet_length(stream):
    # my implementation
    packet_length = sum(len(packet[IP]) for packet in stream)
    return packet_length
    pass


