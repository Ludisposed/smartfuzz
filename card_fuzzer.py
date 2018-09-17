import logging

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.sw.SWExceptions import SWException
from smartcard.Exceptions import CardRequestTimeoutException

class SmartCardFuzzer():
    # Constants for logging a succes
    class Status():
        SUCCES = 0
        FAILED = 1
        PARAM_FAIL = 2

    # Constanst for determining the succes from the status values
    BAD_INSTRUCTIONS = [0x20, 0x24]
    SUCCESS_LIST_RESP = [
                            0x90, # Success
                            0x61, # More Data
                            0x67, # Wrong Length
                            0x6c, # Wrong Length
                            0x6a, # Referenced Data not found
                        ]
    SUCCESS_BAD_PARAM_RESP = [(0x6a, 0x86)]     # Incorrect Paramters
    SUCCESS_FAIL_RESP = [(0x6a, 0x81)]          # Function not supported
    UNSUPPORTED_RESP = [(0x6E, 0x00)]           # Class not supported

    def __init__(self, timeout=30, log_file='smart_fuzzer.log'):
        logging.basicConfig(filename=log_file, level=logging.DEBUG)
        self.timeout = timeout
        self.cardservice = self.__get_card()

    def __get_card(self):
        '''
        This method will get the first card from the cardreader
        Afterwards it will connect to the card and returns it service

        returns:
            cardservice: The cardservice which has a connection with the card

        raises:
            A timeout excpetion if no card was found
        '''
        cardtype = AnyCardType()
        cardrequest = CardRequest(timeout=self.timeout, cardType=cardtype)
        cardservice = cardrequest.waitforcard()
        cardservice.connection.connect()
        return cardservice

    def __send_apdu(self, _class, instruction, p1, p2):
        '''
        This will send and logs an apdu command to the card

        returns:
            response: The response of the command
            sw1: The first status value
            sw2: The second status value
        '''
        apdu = [_class, instruction, p1, p2]
        logging.info(f'Send: {str(apdu)}')
        response, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        logging.info(f'Returned: {response} {sw1} {sw2}')
        return response, sw1, sw2

    def __get_succes(self, sw1, sw2):
        '''
        A function to determine if we encountered a Succes

        args:
            sw1: The first status value
            sw2: the second status value
        
        returns:
            a constant succes

        '''
        if sw1 in self.SUCCESS_LIST_RESP \
           and (sw1, sw2) not in self.SUCCESS_FAIL_RESP \
           and (sw1, sw2) not in self.SUCCESS_BAD_PARAM_RESP:
            logging.info('Apdu command succes!')
            return self.Status.SUCCES
        elif (sw1, sw2) in self.SUCCESS_BAD_PARAM_RESP:
            logging.info('Got partial succes, bruteforce all the params!')
            return self.Status.PARAM_FAIL
        else:
            logging.info(f'Apdu command failed!')
            return self.Status.FAILED

    def _class_fuzzer(self):
        '''
        This will fuzz all the valid classes in the card

        yields:
            _class: If the response was supported
        '''
        for _class in range(0xFF + 1):
            # Set as default failure, in case of exception
            sw1, sw2 = self.UNSUPPORTED_RESP[0]
            try:
                response, sw1, sw2 = self.__send_apdu(_class, 0x00, 0x00, 0x00)
            except SWException as e:
                logging.info(f'Got SWException {e}')
            except Exception as e:
                logging.warning(f'{e}\nSomething went horribly wrong!')
            
            # If it is supported we call it a succes!
            if (sw1, sw2) not in self.UNSUPPORTED_RESP:
                yield _class

    def _instruction_fuzzer(self, _class):
        '''
        This will fuzz all the valid instruction in the card

        args:
            _class: A valid class instruction

        yields:
            A succesful apdu instruction
            (_class, instuction, param1, param2)
        '''
        for instruction in range(0xFF + 1):
            if instruction in self.BAD_INSTRUCTIONS:
                # We don't want to lock up the card ;)
                continue
            
            respsonse, sw1, sw2 = self.__send_apdu(_class, instruction, 0x00, 0x00)
            succes = self.__get_succes(sw1, sw2)
            if succes == self.Status.SUCCES:
                yield (_class, instruction, 0x00, 0x00)
            elif succes == self.Status.PARAM_FAIL:
                yield from self.param_fuzzer(_class, instruction)

    def _param_fuzzer(self, _class, instruction):
        '''
        This will fuzz all the possible parameters for an instruction

        args:
            _class: A valid class instruction
            instruction: A valid instruction

        yields:
            A succesful apdu instruction
            (_class, instuction, param1, param2)
        '''
        for p1 in range(0xff + 1):
            for p2 in range(0xff + 1):
                response, sw1, sw2 = self.__send_apdu(_class, instruction, p1, p2)
                succes = self.__get_succes(sw1, sw2)
                if succes == self.Status.SUCCES:
                    yield (_class, ins, p1, p2)

    def fuzz(self):
        '''
        The main function that will fuzz all possible apdu commands

        yields:
            A succesfol apdu instruction
            (_class, instuction, param1, param2)
        '''
        for valid_class in self._class_fuzzer():
            for valid in self._instruction_fuzzer(valid_class):
                yield valid

def main():
    smart_fuzzer = SmartCardFuzzer()
    for apdu in smart_fuzzer.fuzz():
        print(f"Found valid apdu command {apdu}")

if __name__ == '__main__':
    main()