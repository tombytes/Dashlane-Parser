

#MUST RUN ON 64BIT VERSION OF PYTHON 3
#32BIT VERSION = MemoryError


import re
import struct
import time




# if match <KWGeneratedPassword>:
#     seek 38 bytes from start "<", 
#         then collect the next 24 bytes (thats the "AuthId") 
#     seek 143 from start or 51 from end of "AuthId"
#         then collect until you reach a ] (thats the Domain)
#     seek 57 from end of Domain  
#         then collect the next 10 (thats the Generated Date)
#     seek 47 from end of Generated Date  
#         then collect the next 36 (thats the "Id")
#     seek 59 from end of "Id"
#         then collect the next 10 (thats the Last Backup Time)
#     seek 52 from the end of Last Backup Time    
#         then collect the next 12 (thats the password)

def getDashGenPassword(infile,outfile):
    ''' Looks for the start of the data block
        that contains the Dashlane Generated Password data
             
    '''
    data_list = set()
    FindGenPW = b'\x3C\x4B\x57\x47\x65\x6E\x65\x72\x61\x74\x65\x64\x50\x61\x73\x73\x77\x6F\x72\x64\x3E\x3C\x4B\x57\x44\x61\x74\x61\x49\x74\x65\x6D\x20\x6B\x65\x79\x3D\x22\x41\x75\x74\x68\x49\x64\x22'#\x3E\x3C\x21\x5B\x43\x44\x41\x54\x41\x5B\x7B'
        #'<KWGeneratedPassword><KWDataItem key="AuthId"'
    
    with open(outfile, "wb") as fo:
        with open(infile, "rb") as fi:
 
            for match in re.finditer(FindGenPW,fi.read()):
                fi.seek(match.start())
                print('Offset: '+str(fi.tell())+'\n') #Gives me the the starting offset of EVERY match.
                AuthId=struct.unpack('55x38s', fi.read (93))
                # data_list.add(AuthId)
                print('AuthId: '+str(AuthId[0])+'\n')
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
                                # data_list.add(Domain)
                                # return data_list
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
                                # data_list.add(Id)
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
                                #LastBackTime = (int.from_bytes(keep4[6:20], byteorder='big')
                                LastBackTime=(str(keep4[6:20]))

                                #LBT = time.gmtime(LastBackTime)
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
                # data_list.add(AuthId)
                #return data_list 
                #Placing the dedupe here allows all the values to print once, but only prints the first match.
                #Placing the dedupe above print area prevents anything after AuthId from printing at all, but get all the matches. 




                #If the data has been partially overwritten and is missing the end character ']' it continues. 

                #Because of the high potential for corrupted data, the character limits were set to limit overrun. 
                #If formatting does not appear to be correct, manually inspect the offset location.
                #The most likely cause for incorrect format or incomplete data is is corruption.



                
               
                
                
                
                
        





if __name__ == "__main__":
    infile = 'dellxps.mem'
    outfile = 'dashlane.txt'

    #infile = input('Enter a pcap file to process: ')
    #outfile = input('Enter an output file (will be overwritten if it exists): ')
    getDashGenPassword(infile,outfile)



