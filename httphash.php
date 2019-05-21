<?php
declare(strict_types = 1);

  namespace httphash;

   /*
    *
    *   HTTPhash transaction class
    *   requires PHP >= 7.2 libcurl and libsodium
    *
    *   USAGE:
    *   ---------------------------------------
    *   require_once("PATH_TO_THIS_FILE");
    *   $httphash = new httphash\httphash($rawdata);
    *   $server_json_response = $httphash->response;
    *
    *   CRYPTOBOX INFORMATION:
    *   ---------------------------------------
    *   https://nacl.cr.yp.to/box.html
    *
    */

  class httphash
  {

    #HTTPHASH CUSTOM MODIFICATION-----------------------------------------------------------------------------
    #
    #SERVER HOST
    private CONST MY_HTTPHASH_HOST = "https://hostname.xxx/";
    #SET HTTP AUTH IF REQUIRED ELSE LEAVE BLANK
    private CONST MY_HTTPHASH_HOST_USERPWD = ""; 
    #HOST ADDR (as shown at https://hostname.xxx/serverinfo)
    private CONST MY_HTTPHASH_HOST_ADDR = "";
    #APPLICATION ACCOUNT PRIVATE KEY
    private CONST MY_HTTPHASH_SKEY = "";
    #APPLICATION ACCOUNT PUBLIC ADDRESS
    private CONST MY_HTTPHASH_ADDR = "";
    #
    #ENDOF HTTPHASH CUSTOM MODIFICATION------------------------------------------------------------------------


    private $curl;

    private $encrypted, $decrypted, $sharedkey, $nonce, $pack;

    public $response;


    function __construct(string &$data="")
    {

      $this->curl = curl_init();
      curl_setopt($this->curl, CURLOPT_URL, self::MY_HTTPHASH_HOST . "transaction");
      curl_setopt($this->curl, CURLOPT_POST, 1);
      curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, false);
      curl_setopt($this->curl, CURLOPT_HEADER, false);
      curl_setopt($this->curl, CURLOPT_BINARYTRANSFER, true);
      curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, true);
      if(self::MY_HTTPHASH_HOST_USERPWD!=""){ curl_setopt($this->curl, CURLOPT_USERPWD, self::MY_HTTPHASH_HOST_USERPWD); }

      $this->decrypted = $data;
      $this->sharedkey = sodium_crypto_box_keypair_from_secretkey_and_publickey(

        sodium_hex2bin(self::MY_HTTPHASH_SKEY),
        sodium_hex2bin(substr(self::MY_HTTPHASH_HOST_ADDR, 2))

      );
      $this->nonce=sodium_bin2hex(random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES));
      $this->prepareTransaction();
      $this->sendTransaction();

		}

    function __destruct()
    {

      if($this->encrypted){ sodium_memzero($this->encrypted); }
      if($this->decrypted){ sodium_memzero($this->decrypted); }
      if($this->sharedkey){ sodium_memzero($this->sharedkey); }
      curl_close($this->curl);

    }

    private function prepareTransaction()
    {

      $this->encrypted=sodium_bin2hex(

        sodium_crypto_box(

          $this->decrypted,
          sodium_hex2bin($this->nonce),
          $this->sharedkey

        )

      );

      $this->pack = self::MY_HTTPHASH_ADDR . ":" . $this->nonce . ":" . $this->encrypted;

    }

    private function sendTransaction()
    {

      curl_setopt($this->curl, CURLOPT_POSTFIELDS, "data=" . $this->pack);
      $this->response = curl_exec($this->curl);

    }


  }

?>
