<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace WhoisParser
 */
namespace WhoisParser;

/**
 * Template for .UK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Nominet extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Registrant:[\r\n](.*?)[\r\n]{2}/is',
            2 => '/Name servers:[\r\n](.*?)[\r\n]{2}/is',
            3 => '/Relevant dates:[\r\n](.*?)[\r\n]{2}/is',
            4 => '/Registrar:[\r\n](.*?)[\r\n]{2}$/is'
    );

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/^(?>[\x20\t]+)(.+)$/im' => 'contacts:owner:name'), 
            2 => array(
                    '/^(?>[\x20\t]+)(.+)$/im' => 'nameserver'),
            3 => array(
                    '/Expiry date:(?>[\x20\t]+)(.+)$/im' => 'expires', 
                    '/Registered on:(?>[\x20\t]+)(.+)$/im' => 'created',
                    '/Last updated:(?>[\x20\t]+)(.+)$/im' => 'changed'),
            4 => array(
                    '/^(?>[\x20\t]+)(.+)$/im' => 'registrar:name',
                    '/URL: (.+)$/im' => 'registrar:url')
    );

    /**
     * RegEx to check availability of the domain name
     *
     * Look for this "This domain name has not been registered"
     * 
     * @var string
     * @access protected
     */
    protected $available = '/(This domain name has not been registered)/i';

    /**
     * After parsing ...
     * 
     * If dnssec was matched before it we switch dnssec to true otherwise to false
     * 
	 * @param  object $whoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}