# *Trustless BTC recovery* #
*Trustless BTC recovery* is an open source wallet extraction tool. There are a lot of services providing password recovery, like [UwSoftWare](https://uwsoftware.be/index.php/bitcoin-recovery-service/). For these services to work, they need your wallet information. There are tools for extracting this information, but all require advanced computer knowledge to access the terminal. This tool provides a GUI to do the extracting. Additionally it only extracts the information needed for bruteforcing the password. **It doesn't extract information that can be used to access your funds**. Therefor you can give the extracted data to services without trusting them.

![Example screen](/screenshot.png)

## Quick Start ##
Quick start to extract the information from your wallet.

 * Windows:
    * Download and install [python 2.7](http://www.python.org/ftp/python/2.7.2/python-2.7.2.msi)
    * Install [ActiveCtl](https://www.activestate.com/activetcl/downloads)
    * Download [script](https://cdn.rawgit.com/UwSoftWare/trustless_btc_recovery/master/trustless_btc_recovery.py)
    * Double click the script to execute and follow the steps
 * Linux (Ubuntu):
    * Install python - sudo apt-get install python
    * Install Tkinter - sudo apt-get install python-tk
    * Download the [script](https://cdn.rawgit.com/UwSoftWare/trustless_btc_recovery/master/trustless_btc_recovery.py) 
    * Optionally set the nautilus browser to run scripts [1](https://stackoverflow.com/a/26439671)
    * Double click the script to execute and follow the steps
    
## Supported wallets ##
At the moment the following wallets are supported. More will be added.

 * [Bitcoin Core](https://bitcoincore.org/)
 * [Blockchain.info](https://blockchain.info/wallet)
       
## Trustless ##
The extraction method makes sure no information is extracted that could lead to having access to the funds. But it is advised to create a new wallet and transfer the funds after a successfull recovery.
With the Bitcoin Core wallet this is done by sending the encryption details and some encrypted reserve addresseses that aren't used. If the encrypted addresses can be decrypted, the password was found. A method that has been proven by [Dave](https://bitcointalk.org/index.php?topic=240779.20)
The blockchain method only send the encryption details, no addresses. If the details can be decrypted, a structure should be found in the encrypted data. 
This is more secure as the wallet id and no addresses are revealed.
       
## In depth ##
This programm is based on [pywallet](https://github.com/jackjack-jj/pywallet), [btcrecover](https://github.com/gurnec/btcrecover) and [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper). All tools have a lot of more options for enhanced recovery options, but lack a user friendly interface. This tool is a dumb-down version with a GUI to aid users to extract their wallet information for password recovery on a simple way. It was created by [UwSoftWare](https://uwsoftware.be/index.php/bitcoin-recovery-service/) to aid non-technical people. **By putting the software in opensource, the community can guard the safety of the extraction techniques.**

## Blame list ##
When doing the recovery, most people are more than happy to pay the fees of the recovery service. They are needed because the recovery services operate GPU clusters that costs more than 30 dollar per hour. A recovery can easily cost 2000+ dollar if the machine runs 3 days. Though there are persons not paying the fee or persons stealing wallets [1](https://www.reddit.com/r/Bitcoin/comments/46fcfo/wwwwalletrecoveryservicescom_scam/) and asking the recovery service for assistence. These persons and identifiers for those wallets will be listed here. As we want to help honest people, the upcoming recovery services can be warned.

- No one yet!

You can open merge requests for this.

## License ##
The software is open source and can be adapted, but there should always contain a contribution to 'UwSoftWare Recovery Service'

If you find *Trustless BTC recovery* helpful, please consider a small donation:
**[1NsJm5sW7x3wKgAeNyUuTCsbi9Yk3dQrgv](bitcoin:1NsJm5sW7x3wKgAeNyUuTCsbi9Yk3dQrgv?label=tip)**
