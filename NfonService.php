<?php
namespace App\Service;

use Symfony\Component\HttpClient\HttpClient;

class NfonService
{
    private string $pubKey = '';
    private string $privKey = '';
    private string $systemId = '';
    private const BASE_URI = 'https://portal-api.nfon.net:8090';
    private const API_URI = '/api/customers/';
    private $httpClient;

    private const CONTENT_TYPE = 'application/json';

    public function __construct()
    {
        $this->httpClient = HttpClient::create();
        if(isset($_ENV['NFON_PUBLIC_KEY']))
            $this->pubKey = $_ENV['NFON_PUBLIC_KEY'];
        if(isset($_ENV['NFON_PRIVATE_KEY']))
            $this->privKey = $_ENV['NFON_PRIVATE_KEY'];
        if(isset($_ENV['NFON_SYSTEM_ID']))
            $this->systemId = $_ENV['NFON_SYSTEM_ID'];
    }

    public function setup(string $pubKey, string $privKey, string $systemId)
    {
        $this->pubKey = $pubKey;
        $this->privKey = $privKey;
        $this->systemId = $systemId;
    }

    private function prepare($method, $path, $data)
    {
        $utcDateTime = gmdate('D, d M Y G:i:s e');
        $contentMD5Sum = md5($data);
        $contentLength = strlen(($data));
        $stringToSign = $method . "\n"
            . $contentMD5Sum . "\n"
            . self::CONTENT_TYPE . "\n"
            . $utcDateTime . "\n"
            . $path;
        $hmacSignature = base64_encode(hash_hmac('SHA1', utf8_encode($stringToSign), utf8_encode($this->privKey), true));

        return [
            'authorization' => 'NFON-API ' . $this->pubKey . ':' . $hmacSignature,
            'contentMD5'   => $contentMD5Sum,
            'utcDateTime'   => $utcDateTime,
            'contentLength' => $contentLength
        ];
    }

    private function request(string $mode, string $path, string $data = null)
    {
        $headerData = self::prepare($mode, self::API_URI . $this->systemId . $path, $data);
        $response = $this->httpClient->request(
            $mode,
            self::BASE_URI . self::API_URI . $this->systemId . $path,
            [
                'headers' => [
                    'Authorization'     => $headerData['authorization'],
                    'Content-MD5'       => $headerData['contentMD5'],
                    'Content-Length'    => $headerData['contentLength'],
                    'Content-Type'      => self::CONTENT_TYPE,
                    'x-nfon-date'       => $headerData['utcDateTime']
                ],
                'body' => $data
            ]
        );
        return json_decode($response->getContent());
    }

    public function getApiVersion()
    {
        $response = $this->httpClient->request('GET', self::BASE_URI . '/api/version');
        return json_decode($response->getContent());
    }

    public function get(string $path)
    {
        return $this->request('GET', $path);
    }

    public function put(string $path, $data)
    {
        return $this->request('PUT', $path, $data);
    }

    public function post(string $path, $data)
    {
        return $this->request('POST', $path, $data);
    }

    public function delete(string $path)
    {
        return $this->request('DELETE', $path);
    }
}