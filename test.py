#!/usr/bin/python

import shiftcipher

def main():
  func1 = 'enc'
  key = '3'
  msg1 = 'This is a dog!'
  rslt1 = shiftcipher.calc_cipher_result(func1,key,msg1)

  shiftcipher.disp_output(func1,key,msg1,rslt1)


if __name__ == "__main__":
  main()
