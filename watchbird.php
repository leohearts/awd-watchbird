<?php
/*

A Simple PHP WAF for AWD

Credits:
	[AWD_PHP watchbird] (Original WAF Framework)
	[Longlone](https://github.com/WAY29) (Configuring keyword and upload protection, Global optimization)
	[Leohearts](https://ytoworld.tk) (PHP Reverse proxy, Response body detection, LD_PRELOAD keyword detection)
	[guoqing](https://blog.izgq.net/archives/1029/) (Function: getFormData(), Regenerating RAW multipart/form-data post data)(CC BY-NC-SA 4.0)

Lisence:
	GNU AGPLv3 (GNU Affero General Public License v3.0)
	https://choosealicense.com/licenses/agpl-3.0/

		Permissions			Conditions							Limitations

		Commercial use		Disclose source						Liability
		Distribution		License and copyright notice		Warranty
		Modification		Network use is distribution
		Patent use			Same license
		Private use			State changes

	Attribution-NonCommercial-ShareAlike 4.0 International （CC BY-NC-SA 4.0）	(For Function: getFormData() Only)
	https://creativecommons.org/licenses/by-nc-sa/4.0/

		You are free to:
		Share — copy and redistribute the material in any medium or format
		Adapt — remix, transform, and build upon the material
		Under the following terms:
		Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

		NonCommercial — You may not use the material for commercial purposes.

		ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

		No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.
	
*/


// 功能开启选项
$os = 'linux';  // 操作系统,填linux/win,影响日志存放目录
$flag_path = '/flag';  // 自己flag所在的路径
$LDPRELOAD_PATH = '/var/www/html/waf.so';	//共享库路径
$level = 4;  // 0~4 等级越高,防护能力越强,默认为4
error_reporting(0);

// level处理
$waf_headers = 0;  // headers防御
$waf_ddos = 0;  // ddos防御
$waf_upload = 0;  // 上传防御
$waf_special_char = 0; // 特殊字符防御
$waf_sql = 0;  // sql防御
$waf_rce = 0;  // rce防御
$waf_ldpreload = 0;	//基于LD_PRELOAD的rce防护
$waf_lfi = 0;  // LFI/LFR 防御
$waf_unserialize = 0; // phar反序列化防御
$waf_flag = 0;  // getflag防御
$flag_content_match = 0; // 匹配响应中有无flag特征
$debug = 0;  // debug模式
$allow_ddos_time = 3;  // 每秒最多10个访问 

if ($level >= 1){  // 开启upload,lfi防御
	$waf_upload = 1;
	$waf_lfi = 1;
} 
if ($level >= 2){  // 开启getflag,unserialize,rce防御
	$waf_flag = 1;
	$waf_unserialize = 1;
	$waf_rce = 1;
	$waf_ldpreload = 1;
} 
if ($level >= 3){  // 开启headers,ddos,深度检测防御
	$waf_headers = 1;
	$waf_ddos = 1;
	$flag_content_match = 1;
}
if ($level == 4){  // 开启sql,special_char防御  
	$waf_sql = 1;
	$waf_special_char = 1;
}
function get_fake_flag(){
	global $flag_path;
	$flag = trim(file_get_contents($flag_path));
	$str="QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm";
	str_shuffle($str);
	$fake_flag='flag{'.substr(str_shuffle($str),0,strlen($flag)-6).'}';
	return $fake_flag;
}

function get_preg_flag(){  // 获取自己flag的正则表达式并保存在文件里
	global $flag_path;
	$result = '';
	$flag = file_get_contents($flag_path);
	$flag = trim($flag);
	if(strlen($flag) >= 18)
	{
		$flag1 = substr($flag, 0, strlen($flag)/3);
		$flag1 = preg_quote($flag1, '/');
		$result .= $flag1.'*|';
		$flag2 = substr($flag, strlen($flag)/3, strlen($flag)*2/3);
		$flag2 = preg_quote($flag2, '/');
		$result .= $flag2.'*|';
		$flag3 = substr($flag, strlen($flag)*2/3);
		$flag3 = preg_quote($flag3, '/');
		$result .= $flag3.'*|';
	}else{
		$result = 'flag{|'.preg_quote($flag).'|';
	}
	// echo $result;
	return $result;
}

// 其他配置
$waf_fake_flag = "flag{Longlone:W0r1<_HaRd3r}";  // 虚假flag,需开启waf_flag
$waf_fake_flag2 = get_fake_flag();  //	高级的虚假flag,用于当对面即将获得flag但是被深度检测拦截的时候
// $content_disallow = "/".get_preg_flag(). "not_a_regular_exression/i"; //  一定要保证不和正常内容冲突
$content_disallow = '/'.trim(file_get_contents($flag_path)).'/'; //  一定要保证不和正常内容冲突
$remote_ip = "127.0.0.1";	//	服务器ip
$remote_port = 80;	//	服务器端口

//名单配置
$upload_whitelist="/jpg|png|gif|txt/i";  // upload白名单
$sql_blacklist="/drop |dumpfile\b|INTO FILE|outfile\b|load_file|multipoint\(/i";
$rce_blacklist = "/`|base64_encode|base64_decode|strrev|eval\(|assert\(|file_put_contents|fwrite|curl_exec\(|passthru\(|exec\(|dl\(|openlog|syslog|readlink|symlink|popepassthru|preg_replace|create_function|array_map|call_user_func|array_filter|usort|stream_socket_server|pcntl_exec|passthru|exec\(|system\(|chroot\(|scandir\(|chgrp\(|chown|shell_exec|proc_open|proc_get_status|popen\(|ini_alter|ini_restore|ini_set|_GET|_POST|_COOKIE|_FILE|ini_alter|ini_restore|ini_set|_GET|_POST|_COOKIE|_FILE/i";

class watchbird{
	private $request_url;
	private $request_method;
	private $request_data;
	private $headers;
	private $raw;
	private $dir;
	private $logdir;
	private $uploaddir;
	private $allow_time;
	private $response_content;
	/*
	watchbird类
	*/

// 自动部署构造方法
function __construct(){
	//echo $_SERVER['SERVER_PORT']."\n";
	global $os, $waf_upload, $allow_ddos_time, $waf_headers, $waf_ddos, $content_disallow, $flag_content_match, $waf_fake_flag2, $waf_ldpreload, $LDPRELOAD_PATH;
	if ($os == 'linux')
	{
		$this->dir = '/tmp/watchbird/';
		$this->logdir = $this->dir.'log/';
		$this->uploaddir = $this->dir.'upload/';
		$this->ipdir = $this->dir.'ip/';
	}
	elseif($os == 'win')
	{
		$this->dir = 'D:\\watchbird\\';
		$this->logdir = $this->dir.'log\\';
		$this->uploaddir = $this->dir.'upload\\';
		$this->ipdir = $this->dir.'ip\\';
	}
	if ($waf_ldpreload == 1) {
		putenv("LD_PRELOAD=" . $LDPRELOAD_PATH);
	}
	$this->headers = getallheaders(); //获取header  
	if(isset($_SERVER['HTTP_ISSELF'])){
		return 0;
	}
	$this->allow_time = $allow_ddos_time;  // 获取每秒最大访问次数
	if ($waf_ddos == true){
		$this->watch_ddos();
	}
	$this->e_mkdir($this->dir);
	$this->e_mkdir($this->logdir);
	$this->e_mkdir($this->uploaddir);
	$this->e_mkdir($this->ipdir);
	$this->request_url = $this->filter_0x25(urldecode($_SERVER['REQUEST_URI'])); //	获取url来进行检测
	$this->request_data = file_get_contents('php://input');	//	获取post
	if ($waf_headers == true)
	{   
		$this->watch_headers();  // 监测headers
	}
	$this->write_access_log_probably();  //	记录访问纪录, 类似于日志
	$this->write_access_logs_detailed();  //	记录详细访问请求包  
	if ($waf_upload==true) {
		$this->watch_upload();  // 记录上传纪录
	}
	if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
		$method = $_SERVER['REQUEST_METHOD'];
		$this->write_attack_log("Catch attack: Suspicious method [ ".$method."] ");
	}
	foreach ($_GET as $keywords){   //	监测GET参数，出现问题则记录
		$this->watch_attack_keyword($this->watch_special_char($keywords)); 
	}
	if  ($this->request_data != '')
	{
		foreach ($_POST as $keywords){   //	监测POST参数，出现问题则记录
			$this->watch_attack_keyword($this->watch_special_char($keywords)); 
		}
	}
	if ($flag_content_match){   //	深度检测响应包
		$this->getcont();  // 开始自检
		if (preg_match($content_disallow, $this->response_content)!==0){
				$this->write_flag_log();
				die($waf_fake_flag2);
		}
		else {
			$co=explode("\r\n\r\n",$this->response_content,2)[1];
			$raw_header=explode("\r\n\r\n",$this->response_content,2)[0];
			$res_header = explode("\r\n",explode("\r\n",$raw_header,2)[1]);
			foreach ($res_header as $leo1){
				header($leo1,false);
			}
			header("Content-Encoding: identity");
			header("Transfer-Encoding: identity");
			if (preg_match("/^[0-9]{4}/",$co)){
				$co=substr($co,4);
			}
			$co=substr($co,strpos($co,pack("CCC",0xef,0xbb,0xbf)));  // 处理BOM头
			if (substr($co,0,3) == pack("CCC",0xef,0xbb,0xbf)){
				$co=substr($co,3);
			}
			if (substr($co,-7)=="\r\n0\r\n\r\n"){
				$co=rtrim($co,"\r\n0\r\n\r\n");
				$co .= "\r\n\r\n";
			}
			die($co);  // 将内容返回给用户
		}
	}
}

/*
判断文件夹是否存在并创建文件夹
*/
function e_mkdir($folder){
	if (is_dir($folder) == false)
	{
		mkdir($folder, 0777, true);
		return true;
	}	
	return false;
}

/*
删除文件夹下所有文件
*/
function deldir($dir) {
	$dh=opendir($dir);
	while ($file=readdir($dh)) {
		if($file!="." && $file!="..") {
			$fullpath=$dir."/".$file;
			if(!is_dir($fullpath)) {
				unlink($fullpath);
			} 
			else {
				$this->deldir($fullpath);
			}
		}
	}
}

/*
DDOS防御
*/
function watch_ddos(){
	$IP = $_SERVER['REMOTE_ADDR'];
	$IP = str_replace(":", '_', $IP);
	$date = date('H_i_s');
	$IP_dir = $this->ipdir . '/' . $IP . '/';
	$this->e_mkdir($IP_dir);
	$IP_date_file = $IP_dir . $date . '_log.txt';
	if (is_file($IP_date_file))
	{
		$time = intval(file_get_contents($IP_date_file));
		$time += 1;
		if ($time > $this->allow_time)
		{
			die('Access Denied.');
		}
		else{
			file_put_contents($IP_date_file, $time, LOCK_EX);
		}
	}
	else{
		$this->deldir($IP_dir);
		file_put_contents($IP_date_file, 1, LOCK_EX);
	}
}   

/*
监测headers
*/
function watch_headers(){
	global $sql_blacklist, $rce_blacklist;
	foreach($this->headers as $k=>$v) {
		if (preg_match($sql_blacklist, urldecode($v)) || preg_match($rce_blacklist, urldecode($v))) {
			$this->headers[$k] = '';
			// $URI = explode('?',$this->request_url);
			// header('Location: http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$URI[0]);
			die("Access Denied..");
		}
	}
}


/*
监测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function watch_special_char($str){
	global $waf_special_char;
	$txt = '';
	for($i=0;$i<strlen($str);$i++){
		$ascii = ord($str[$i]);
		if($ascii>126 || $ascii < 32){ //	有中文这里要修改
			if(!in_array($ascii, array(9,10,13))){
				$txt .= "Interrupt";
			}else{
				$txt .= "  Catch attack: Suspected attack character < ".$str[$i]. " > ";
			}
			break;
		}
		if (preg_match("/\||\`|\;|\,|\'|\"|<|>/", $str[$i]))
		{
			$txt .= "  Catch attack: Suspected attack character < ".$str[$i]." > ";
			break;
		}
	}
	if ($txt != '')
	{
		$this->write_attack_log($txt);
		if($waf_special_char == true){
			$this->redirect();
			die(); 
		}
	}
	return $str;
}
/*
监测文件上传
*/
function watch_upload(){
	global $upload_whitelist;
	foreach ($_FILES as $key => $value) {
		if($_FILES[$key]['error'] == 0){
			$ext = substr(strrchr($_FILES[$key]["name"], '.'), 1);
			$this->write_attack_log("Catch attack: < Evil Upload, please check ".$this->uploaddir." dir > ");
			copy($_FILES[$key]["tmp_name"], $this->uploaddir.date("d_H_i_s").'.'.$ext.'.txt');
			if(!preg_match($upload_whitelist, $ext))
			{
				unlink($_FILES[$key]['tmp_name']);
				echo 'Upload success! Check upload/'.substr(md5($_FILES[$key]["name"]), 0, rand(10, 30)).'.'.$ext;
				die();
			}
		}
	}
}

/*
监测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
	if(strpos($str,"%25") !== false){
		$str = str_replace("%25", "%", $str);
		return $this->filter_0x25($str);
	}else{
		return $str;
	}
}

/*
对非法请求进行重定向
*/
function redirect(){
	$URI = explode('?',$this->request_url);
	header('Location: http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$URI[0]);
	die();
}

/*
监测攻击关键字
*/
function watch_attack_keyword($str){
	global $sql_blacklist, $rce_blacklist, $waf_sql, $waf_lfi, $waf_rce, $waf_unserialize, $waf_flag, $waf_fake_flag;
	if(preg_match($sql_blacklist, $str)){
		$this->write_attack_log("Catch attack: < SQLI > ");
		if($waf_sql == true){
			$this->redirect();
		}
	}
	if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
		$tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
		if(preg_match("/\.\.|.*\.php[2357]{0,1}|\.phtml/i", $tmp)){ 
			$this->write_attack_log("Catch attack: < LFI/LFR > ");
			if($waf_lfi == true){
				$this->redirect();
			}
		}
	}else{
		$this->write_attack_log("Catch attack: < LFI/LFR > ");
		if($waf_lfi == true){
			$this->redirect();
		}
	}
	if(preg_match($rce_blacklist, $str)){
		$this->write_attack_log("Catch attack: < RCE > ");
		if($waf_rce == true){
			$this->redirect(); 
		}
	}
	if(preg_match("/phar|zip|compress.bzip2|compress.zlib/i", $str)){
		$this->write_attack_log("Catch attack: < phar unserialize >");
		if($waf_unserialize == true){
			$this->redirect(); 
		}
	}
	if(preg_match("/flag/i", $str)){
		$this->write_attack_log("Catch attack: < !!GETFLAG!! >");
		if($waf_flag == true){
			print($waf_fake_flag);
			die(); 
		}
	}
}


//	记录每次大概访问记录，类似日志，以便在详细记录中查找
function write_access_log_probably() { 
	$tmp = sha1("Syclover")."\n";
	$tmp .= "[" . date('y-m-d H:i:s') . "]" . $_SERVER['REQUEST_METHOD'].' '.$this->request_url.' '.$_SERVER['SERVER_PROTOCOL'];
	if (!empty($this->request_data)){
		$tmp .= "\n".$this->request_data; 
	}
	$tmp .= "\n";
	file_put_contents($this->logdir.'all_requests'.'.txt', $tmp, FILE_APPEND | LOCK_EX);
}

//	记录详细的访问头记录，包括GET POST http头, 以获取waf未检测到的攻击payload
function write_access_logs_detailed(){
	$tmp = sha1("Syclover")."\n";
	$tmp .= "[" . date('y-m-d H:i:s') . "]\n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$this->request_url.' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		if ($k==="isself"){
			continue;
		}
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "\n". $this->request_data . "\n";
	}
	$tmp .= "\n";
	file_put_contents($this->logdir.'web_log'.'.txt', $tmp, FILE_APPEND | LOCK_EX);
}
	
/*
记录攻击payload 第一个参数为记录类型  使用时直接调用函数
*/
function write_attack_log($alert){
	$tmp = sha1("Syclover")."\n";
	$tmp .= "[" . date('y-m-d H:i:s') . "] {".$alert."}\n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$this->request_url.' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		if ($k==="isself"){
			continue;
		}
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "n". $this->request_data . "\n";
	}
	file_put_contents($this->logdir.'under_attack_log.txt', $tmp, FILE_APPEND | LOCK_EX);
	if ($alert == 'Catch attack: < !!GETFLAG!! >')  // 顺便写入另外一个日志
	{
		file_put_contents($this->logdir.'flag_eye_to_eye.txt', $tmp, FILE_APPEND | LOCK_EX);
	}
}



/*
将流量发送到本地服务器进行自检
*/
function getcont(){
	global $debug, $remote_ip, $remote_port;
	$headerstr = "";
	$this->response_content = "";
	$this->headers['isself'] = "true";
	$this->headers['Connection'] = "Close";
	$this->headers["Accept-Encoding"] = "*/*";
	foreach($this->headers as $k => $v) {
		$headerstr .= $k . ': ' . $v . "\r\n";
	}
	$fp = fsockopen($remote_ip, $remote_port, $errno, $errstr, 30);
	if (!$fp) {
			echo "500 Internal Server Error.";
	}
	else {
		$out = $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
		$out .= $headerstr;
		$out .= "\r\n";
		$out .= $this->request_data . "\r\n";
		if ($this->request_data===''&&$_SERVER['REQUEST_METHOD']=="POST"){
			$out .= getFormData();
		}
		fwrite($fp, $out);
		//echo $out;
		while (!feof($fp)) {
			$tmp3 = fgets($fp, 4);
			$this->response_content .= $tmp3;
		}
		fclose($fp);
		if ($debug){
			echo $out;
			echo $this->response_content;
		}
	}
}

/*
当响应包中存在flag时写入日志
*/
function write_flag_log(){
	$tmp = sha1("Syclover")."\n";
	$tmp .= "\nRequest:\n";
	$tmp .= "[" . date('y-m-d H:i:s') . "] \n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		// if ($k==="isself"){
		// 	continue;
		// }
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "\n". $this->request_data . "\n";
	}
	$tmp .= "\nResponse\n";
	$tmp .= $this->response_content;
	file_put_contents($this->logdir.'flag_log.txt', $tmp, FILE_APPEND | LOCK_EX);
}

}

// 还原 rfc1867, rfc2046 格式的FormData, 来自https://blog.izgq.net/archives/1029/
function getFormData(){
	// body-part array
	$body = array();

	// 普通参数
	foreach ($_POST as $key => $value) {
		if (!is_array($value)) {
			$body_part = "Content-Disposition: form-data; name=\"$key\"\r\n";
			$body_part .= "\r\n$value";
			$body[] = $body_part;
		} else {
			// 数组的情况处理 如 param1[]=xxxx
			$result = array();
			convert_array_key($value, $key, $result);
			foreach ($result as $k => $v) {
				$body_part = "Content-Disposition: form-data; name=\"$k\"\r\n";
				$body_part .= "\r\n$v";
				$body[] = $body_part;
			}
		}
	}

	// 上传文件处理
	foreach ($_FILES as $key => $value) {
		if (!is_array($value['type'])) {
			$body_part = "Content-Disposition: form-data; name=\"$key\"; filename=\"{$value['name']}\"\r\n";
			$body_part .= "Content-type: {$value['type']}\r\n";
			$body_part .= "\r\n" . file_get_contents($value['tmp_name']);
			$body[] = $body_part;
		} else {
			// 文件key是数组的情况 如 file1[]=xxxx
			$result = array();
			convert_array_key($value['type'], "", $result);
			foreach ($result as $k => $v) {
				$filename = query_multidimensional_array($value['name'], $k);
				$type = query_multidimensional_array($value['type'], $k);
				$tmp_name = query_multidimensional_array($value['tmp_name'], $k);
				$body_part = "Content-Disposition: form-data; name=\"{$key}{$k}\"; filename=\"{$filename}\"\r\n";
				$body_part .= "Content-type: {$type}\r\n";
				$body_part .= "\r\n" . file_get_contents($tmp_name);
				$body[] = $body_part;
			}
		}
	}

	// 提取boundary
	$boundary = substr($_SERVER['CONTENT_TYPE'], strpos($_SERVER['CONTENT_TYPE'], "=") + 1);
	// multipart-body
	$multipart_body = "--$boundary\r\n";
	// 拼接各个域
	$multipart_body .= implode("\r\n--$boundary\r\n", $body);
	// 最后一个不同的 boundary
	$multipart_body .= "\r\n--$boundary--";

	return $multipart_body;
}

// 直接访问多维数组元素
// query: [0][0] -> $array[0][0]
function query_multidimensional_array(&$array, $query){
	$query = explode('][', substr($query, 1, -1));
	$temp = $array;
	foreach ($query as $key) {
		$temp = $temp[$key];
	}
	return $temp;
}

// DFS将数组变为一维形式
function convert_array_key(&$node, $prefix, &$result){
	if (!is_array($node)) {
		$result[$prefix] = $node;
	} else {
		foreach ($node as $key => $value) {
			convert_array_key($value, "{$prefix}[{$key}]", $result);
		}
	}
}

if (!function_exists('getallheaders'))
{
    function getallheaders()
    {
           $headers = [];
       foreach ($_SERVER as $name => $value)
       {
           if (substr($name, 0, 5) == 'HTTP_'&&$value!='')
           {
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
           }
       }
       return $headers;
    }
}

$watchbird = new watchbird();
