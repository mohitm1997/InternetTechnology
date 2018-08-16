#!/usr/bin/python 

import argparse
import sys

# CS 352 Fizzbuzz Assignment Skeleton
#
# (c) 2018 R. P. Martin under the GPL version 2 license 

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 FizzBuzz')
    parser.add_argument('-s','--start', help='Starting Value', required=True)
    parser.add_argument('-e','--end', help='Ending Value', required=True)

    # parse the input 
    args = vars(parser.parse_args())
    start = int(args['start'])
    end = int(args['end'])

    print("CS 352 fizzbuzz, start at %d, end at %d " % (start,end) )

    # For every number from the start to the end (inclusive):
    
    # if the number is divisible by 3, print "Fizz" (newline) 
    # if the number is divisible by 5, print "Buzz" (newline)
    # if the number is divisible by both 3 and 5, print "FizzBuzz" (newline)
    # if the number is neither divisible by 3 or 5, print the sum of all the previous numbers
    # which have been printed, starting with zero. (newline) 
    	
    if(end < start):
    	print("The end value must be greater than the start value!")
    	return

    count = 0
    x = start

    while(x <= end):
    	if(x % 3 == 0 and x % 5 == 0):
    		print("FizzBuzz")
    		x += 1

    	elif(x % 3 == 0):
    		print("Fizz")
    		x += 1

    	elif(x % 5 == 0):
    		print("Buzz")
    		x += 1

    	else:
    		print(count)
    		count += x
    		x += 1	

    # your code goes here.
            
# create a main function in Python
if __name__ == "__main__":
    main()


