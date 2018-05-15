#dashlane-parser
#Tom Moore
#May 2018
#v1.0

#Run on Python 2.7.14. 
#Previous version worked with Python3 x64, but addition of the fo.write() statements now throws errors. 


import re
import struct
#import time


def getDashGenPassword(infile,outfile):
    ''' Parses Dashlane-Generated Passwords
        from memory captures.
             
    '''
    
    FindGenPW = b'\x3C\x4B\x57\x47\x65\x6E\x65\x72\x61\x74\x65\x64\x50\x61\x73\x73\x77\x6F\x72\x64\x3E\x3C\x4B\x57\x44\x61\x74\x61\x49\x74\x65\x6D\x20\x6B\x65\x79\x3D\x22\x41\x75\x74\x68\x49\x64\x22'#\x3E\x3C\x21\x5B\x43\x44\x41\x54\x41\x5B\x7B'
        #'<KWGeneratedPassword><KWDataItem key="AuthId"'
    
    with open(outfile, "wb") as fo:
        with open(infile, "rb") as fi:
 
            for match in re.finditer(FindGenPW,fi.read()):
                fi.seek(match.start())
                print('Offset: '+str(fi.tell())+'\n') #Gives me the the starting offset of EVERY match.
                fo.write('Offset: '+str(fi.tell())+'\n')
                AuthId=struct.unpack('55x38s', fi.read (93))
                print('AuthId: '+str(AuthId[0])+'\n')
                fo.write('AuthId: '+str(AuthId[0])+'\n')
                keep = b''
                keep2= b''
                keep3= b''
                keep4= b''
                keep5= b''
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep += b
                                Domain = str(keep[6:40])
                            else:
                                break
                        break
                while True:    
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep2 += b
                                GenDate = str(keep2[6:20])
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep3 += b
                                Id = str(keep3[6:50])
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep4 += b
                                LastBackTime=(str(keep4[6:20]))
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep5 += b
                                GenPass = (str(keep5[6:40]))
                            else:
                                break
                        break
                                
                print('Domain: ' +Domain+'\n')                
                print('Generated Date: ' +GenDate+'\n')
                print('Id: ' +Id+'\n')
                print('Last Backup Time: '+LastBackTime+'\n')
                print('Dashlane-Generated Password: '+GenPass+'\n')
                
                fo.write('Domain: ' +Domain+'\n')                
                fo.write('Generated Date: ' +GenDate+'\n')
                fo.write('Id: ' +Id+'\n')
                fo.write('Last Backup Time: '+LastBackTime+'\n')
                fo.write('Dashlane-Generated Password: '+GenPass+'\n\n')
                
                
if __name__ == "__main__":

    infile = input('Enter a memory capture file. Quotes may be necessary if including extensions. (Ex: "memory.vmem"): ')
    outfile = input('Enter an output filename. Quotes may be necessary if including extensions. (Ex: "output.txt"): ')
    getDashGenPassword(infile,outfile)



