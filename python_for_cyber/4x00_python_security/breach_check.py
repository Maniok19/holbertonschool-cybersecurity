#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser(prog='Main',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("--file","-f", help='Input file path', required=True)
    parser.add_argument("--verbose","-v", help='Print debug')
    parser.add_argument("--output","-o", help='Output report file path')
    args = parser.parse_args()


    print("BreachCheck v1.0 startup...")

if __name__ == "__main__":
    main()
