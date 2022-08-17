<?php
/**
 * AkamaiToken.php - An Akamai EdgeAuth Token 2.0 implementation for PHP
 *
 * author: James Mutton <jmutton@akamai.com>
 *
 * Copyright (c) 2011, Akamai Technologies, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Akamai Technologies nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * AkamaiToken
 * Notes:
 */
class Akamai_EdgeAuth_Generate
{

    protected function h2b($str)
    {
        $bin = "";
        $i = 0;
        do {
            $bin .= chr(hexdec($str{$i}.$str{($i + 1)}));
            $i += 2;
        } while ($i < strlen($str));
        return $bin;
    }

    public function generate_token($config)
    {
        // ASSUMES:($algo='sha256', $ip='', $start_time=null, $window=300, $acl=null, $acl_url="", $session_id="", $payload="", $salt="", $key="000000000000", $field_delimiter="~")
        $m_token = $config->get_ip_field();
        $m_token .= $config->get_start_time_field();
        $m_token .= $config->get_expr_field();
        $m_token .= $config->get_acl_field();
        $m_token .= $config->get_session_id_field();
        $m_token .= $config->get_data_field();
        $m_token_digest = (string)$m_token;
        $m_token_digest .= $config->get_url_field();
        $m_token_digest .= $config->get_salt_field();

        // produce the signature and append to the tokenized string
        $signature = hash_hmac($config->get_algo(), rtrim($m_token_digest, $config->get_field_delimiter()), $this->h2b($config->get_key()));
        return $m_token.'hmac='.$signature;
    }
}
