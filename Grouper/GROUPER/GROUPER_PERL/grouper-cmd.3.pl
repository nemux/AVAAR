#!/usr/bin/perl -w
#### grouper-cmd.pl
## Versión 0.3 22-sep-2011
## cambios
## Se agrego un filtros mas para security holes


###### Modules ####

use strict;
#use warnings;
use File::Slurp;        			## Leer una archivo de un solo golpe
use File::List;					## Listar directorios
use POSIX qw/strftime/; 			## Generar fechas
use Spreadsheet::WriteExcel;			## Escribir archivos xls
use Spreadsheet::ParseExcel::Simple;		## Leer archivmos xls 



###### Constantes Globales (j4 j4 j4) ######

my $MOTTO = "More human than human' is our motto";
my $ERROR__unknow = "it should be a human error";

## Acentos en UTF8 http://www.utf8-chartable.de/
my $C__a_acute = chr 0x00E1;
my $C__e_acute = chr 0x00E9;
my $C__i_acute = chr 0x00ED;
my $C__o_acute = chr 0x00F3;
my $C__u_acute = chr 0x00FA;



###### Variables Globales (Configuración del aplicativo) ######

my $FLAG__cmd_option_use_IP_catalog=0;	# Bandera que indica si se debe intentar usar un catalogo de IP's para resolver datos del equipo (hostname, Sistema ativo) y validar Platafomas de servicios
my $FLAG__cmd_option_LANG="es";		# Bandera que indica el catalogo de Vulneranilidades a utilizar segun el idiomas correspondiente a la salida deseada.
my $FLAG__use_IP_catalog;			# Bandera que indica si es posible usar la informaciòn del catalgo de IP's



###### Programa Principal ######

my $C__numArgs = $#ARGV + 1;
my $F__IN_Report_Type = "nbe";#$ARGV[0];	# Tipo de reporetes a procesar: nbe para nessus

print "$MOTTO\n";
S__read_input_files($F__IN_Report_Type);



###### Funciones ######


#### Lee todos los archivos en la carpeta "in" y obtiene de ellos los datos de IP Puerto/Protcolo y Plugin ID
###  $F__NBE_Report_Type 		Tipo de archivo de entrada que espera procesar: nbe para nessus
sub S__read_input_files
{
    my ($F__IN_Report_Type) = @_;
    my @M__IN_File_List;		# Lista de archivos a procesar encontrados en la carpeta IN
    my $F__File;			# Nomre y Ruta de un archivo de la lista de archivos a procesar 
    my $O__search = new File::List("IN");# Nomre y Ruta del directorio a procesar
    my $C__Files;
    
    @M__IN_File_List = 	@{ $O__search->find("\.nbe\$") };# Genera una lista con todos los archivos .nbe
    
    ## Leer cada archivo del directorio IN y obtener IP, Pueto/Protocolo, Plugin ID
    $C__Files = 0;
    foreach $F__File (@M__IN_File_List)
    {
	print "Procesando archivo $F__File\n";
	S__work_reg_items($F__File);
	$C__Files++;
    }
    print "Se procesaron $C__Files Archivos"
}


#### Para cada registro, busca los elementos y genera una fila de resultado
###  $F__IN_SRC  			Nombre y ruta del archivo nbe a procesar
###  $L__plugins  		
sub S__work_reg_items
{
    my ($F__IN_SRC,$L__plugins) = @_;
    my $V__row_data;			# Dato de un registro del archivo nbe
    my @M__plugins;
    my $V__reg_type;			# Tipo de registro: timestamp/results
    my $V__reg_blank1;			# Campo de registro sin contenido Util
    my $V__reg_blank2;			# Campo de registro sin contenido Util
    my $V__reg_service_port_protocol;	# Puerto, Protoclo y Servicio del registro
    my $V__reg_service;			# Servicio del registro
    my $V__reg_port;			# Puerto del registro
    my $V__reg_protocol;		# Protoclo del registro
    my $V__ip_addr;			# IP de registro
    my $V__hostname;			# Hostname de la IP (sacando del catalogo info/IPs.xls)
    my $V__plugin_id;			# Valor del id puglin de un registro
    my $V__plugin_data;			# Datos del plugin (nombre, descripción, solución, CVSS, etc) obtenidos de info/vulnerabilidades.xls
    my $V__plugin_rawdata;		# Datos originales del plugin (nombre, descripción, solución, CVSS, etc) del registro
    my $V__plugin_full;			# Datos originales del plugin (nombre, descripción, solución, CVSS, etc) del registro
    my @M__IN_data;			# Arreglo que contiene todo el archivo .nbe original
   
   
    my $F__Workbook = Spreadsheet::WriteExcel->new("reporte.xls");
    my $M__Worksheet = $F__Workbook->add_worksheet();
    
    my $C__Actual_ROW=1;
    
    #### Establece los posibles formatos a aplicar en el libro de resultados xls  
    my $V__Format_General = $F__Workbook->add_format(font => 'Arial',size => 10,); # Formato General
    $V__Format_General->set_align('center');
    $V__Format_General->set_align('vcenter');
    
    my $V__Format_Mini = $F__Workbook->add_format(font => 'Arial',size => 8,); # Formato General
    $V__Format_Mini->set_align('center');
    $V__Format_Mini->set_align('vcenter');
    
    my $V__Format_CVE = $F__Workbook->add_format(font => 'Arial',size => 8,); # Formato CVE
    $V__Format_CVE->set_text_wrap();
    #$V__Format_CVE->set_align('center');
    $V__Format_CVE->set_align('vcenter');
    
    #my $V__Format_CVE = $F__Workbook->add_format(font => 'Arial',size => 8,); # Formato General
    #$V__Format_CVE->set_text_wrap();
    #$V__Format_CVE->set_align('center');
    #$V__Format_CVE->set_align('vcenter');	
	
    my $V__Format_Tile = $F__Workbook->add_format(font => 'Arial',size => 10,); # Formato de titulos
    $V__Format_Tile->set_bold();
    $V__Format_Tile->set_align('center');
    $V__Format_Tile->set_bg_color(56);
    $V__Format_Tile->set_color('white');
    
    my $V__Format_AltoRiesgo = $F__Workbook->add_format(font => 'Arial',size => 10,);
    $V__Format_AltoRiesgo->set_bg_color('10');
    $V__Format_AltoRiesgo->set_align('center');
    $V__Format_AltoRiesgo->set_align('vcenter');

    my $V__Format_MedioRiesgo = $F__Workbook->add_format(font => 'Arial',size => 10,);
    $V__Format_MedioRiesgo->set_bg_color('13');
    $V__Format_MedioRiesgo->set_align('center');
    $V__Format_MedioRiesgo->set_align('vcenter');

    my $V__Format_BajoRiesgo = $F__Workbook->add_format(font => 'Arial',size => 10,);
    $V__Format_BajoRiesgo->set_bg_color('42');
    $V__Format_BajoRiesgo->set_align('center');
    $V__Format_BajoRiesgo->set_align('vcenter');

    my $V__Format_Vulname = $F__Workbook->add_format(font => 'Arial',size => 10,);
    $V__Format_Vulname->set_bold();
    $V__Format_Vulname->set_align('justify');
    $V__Format_Vulname->set_align('vcenter');

    my $V__Format_Vultext = $F__Workbook->add_format(font => 'Arial',size => 8,);
    $V__Format_Vultext->set_text_wrap();
    #$V__Format_Vultext->set_align('justify');
    $V__Format_Vultext->set_align('vcenter');
   
    my @M__vulnerabylity;
    my $V__vulnerability;
    my $V__IPs;
    my $V__PortProtocol;
    my @M__vulnerability_data;
    my $V__vulnerability_IP;
    my $V__vulnerability_Hostname;
    my $V__vulnerability_name;
    my $V__vulnerability_port;
    my $V__vulnerability_protocol;
    my $V__vulnerability_cve;
    my $V__vulnerability_plataforma;
    my $V__vulnerability_ID;
    my $V__vulnerability_description;
    my $V__vulnerability_solution;
    my $V__vulnerability_riesgo;
    my $V__vulneranility_cvss;
    my $V__vulnerability_sis;
    my $V__vulnerability_tipo;
    my $V__vulnerability_count;		# Total de vulberavilidades encontradas
    my $M__vulnerability_count;		# Total Vulnerabiliades Encontradas por IP
    my $M__vulnerability_high_count;	# Total Vulnerabiliades Altas Encontradas por IP
    my $M__vulnerability_medium_count;	# Total Vulnerabiliades Medias Encontradas por IP
    my $M__vulnerability_low_count;	# Total Vulnerabiliades Bajas Encontradas por IP
    my $V__aux;
    my @M__aux;
    my $V__trash;
    my $V__counter;
   
   
    @M__IN_data = read_file($F__IN_SRC);# Lectura del Archivo completo (raw de herramienta)
   
    open(DATA,">>tmp/data.killme");
    open(INFO,">>tmp/info.txt");
    
    $V__vulnerability_count = 0;
    
    foreach $V__row_data (@M__IN_data)
    {
	if($V__row_data=~/results/) #Solo procesa los registros que empiecen con el texto results
	{
	    #print "\tProcesando registro $V__row_data";
	    ($V__reg_type,$V__reg_blank1,$V__ip_addr,$V__reg_service_port_protocol,$V__plugin_id,$V__reg_blank2,$V__plugin_rawdata) = split(/\|/,$V__row_data);
    
	    $_ = $V__reg_service_port_protocol;
	    s/\(//g;
	    s/\)//g;
	    if (/general/==1)
	    {
		@M__aux = split(/\//,$_);
		$V__reg_service = "general";
		$V__reg_port = "general";
		$V__reg_protocol = $M__aux[1];
	    }
	    else
	    {
		@M__aux = split(/ /,$_);
		$V__reg_service = $M__aux[0];
		$V__aux = $M__aux[1];
		@M__aux = split(/\//,$V__aux);
		$V__reg_port = $M__aux[0];
		$V__reg_protocol = $M__aux[1];
	    }
	    
	    
	    if($V__plugin_id=~/^(\d)/)
	    {
		#print INFO "Procesando $V__plugin_id\n$V__plugin_rawdata\n\n";
		$_ = $V__row_data;
		#modificación para que tome todas la vul
               if(/Risk factor :\n\nLow/==1 ||/Risk factor : Low/==1 || /Risk factor :\\n\\nLow/==1  || /Risk factor : \\n\\nLow/==1 || /Risk factor : Medium/==1 || /Risk factor :\\n\\nMedium/==1 ||/Risk factor :\n\nMedium/==1 ||/Risk factor : \\n\\nMedium/==1 || /Risk factor : High/==1 || /Risk factor :\n\nHigh/==1 || /Risk factor :\\n\\nHigh/==1 || /Risk factor : \\n\\nHigh/==1 || /Risk factor : \\n\\nCritical/==1 || /Risk factor :\\n\\nCritical/==1 || /Risk factor :\n\nCritical/==1)
		{
		    $V__hostname=S__search_hostname($V__ip_addr);
		    $V__vulnerability_sis=S__search_sistema($V__ip_addr);
		    
		    $V__aux="$V__reg_port-$V__reg_protocol";
		    $_ = $V__plugin_data=S__search_plugin_data($V__plugin_id,$V__ip_addr,$V__aux);
		    if (/_UPS_/==1)
		    {
		        print INFO "Se desconoce la informacion del plugin $V__plugin_id\n$V__plugin_rawdata\n\n";
		    }
		    $_ = $V__plugin_data;
		    s/\n/\~/g;
		    $V__plugin_data = $_;
		    print DATA "$V__ip_addr;$V__hostname;$V__reg_protocol;$V__reg_port;$V__plugin_data;$V__vulnerability_sis\n";
		    $V__vulnerability_count++;
		}
	    }
       }
    }    
    close DATA;
    close INFO;
   
    $F__IN_SRC = "tmp/data.killme";

    @M__IN_data = read_file($F__IN_SRC);# Lectura del Archivo completo (procesado de grouper)

    
    #$M__Worksheet->write($C__Actual_ROW, 0, "IP",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 1, "Hostname",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 2, "Protocolo",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 3, "Puerto",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 4, "Nombre de la vulnerabilidad",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 5, "Nessus ID",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 6, "CVE",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 7, "Plataforma",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 8, "Prioridad",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 9, "CVSS",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 10, "Descripci".$C__o_acute."n",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 11, "Soluci".$C__o_acute."n",$V__Format_Tile);
    #$M__Worksheet->write($C__Actual_ROW, 12, "Justificaci".$C__o_acute."n",$V__Format_Tile);

    $M__Worksheet->write($C__Actual_ROW, 0, "Nombre de la vulnerabilidad",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 1, "Nessus ID",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 2, "CVE",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 3, "CVSS",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 4, "Prioridad",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 5, "IP",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 6, "Hostname",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 7, "Protocolo",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 8, "Puerto",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 9, "Plataforma",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 10, "Descripci".$C__o_acute."n",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 11, "Soluci".$C__o_acute."n",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 12, "AUX".$C__o_acute."n",$V__Format_Tile);
    $M__Worksheet->write($C__Actual_ROW, 13, "AUX".$C__o_acute."n",$V__Format_Tile);



    foreach $V__row_data (@M__IN_data)
    {
	$C__Actual_ROW++;
	$C__Actual_ROW++;
	$_ = $V__row_data;
	s/\~/\n/g;
	$V__row_data = $_;
	@M__vulnerability_data = split(/;/,$V__row_data);
	$V__vulnerability_IP = $M__vulnerability_data[0];
	$V__vulnerability_Hostname = $M__vulnerability_data[1];
	$V__vulnerability_protocol = $M__vulnerability_data[2];
	$V__vulnerability_port  = $M__vulnerability_data[3];
	$V__vulnerability_name = $M__vulnerability_data[4];
	$V__vulnerability_ID  = $M__vulnerability_data[5];
	$V__vulnerability_cve = $M__vulnerability_data[6];
	$V__vulnerability_plataforma = $M__vulnerability_data[7];
	$V__vulnerability_riesgo  = $M__vulnerability_data[8];
	$V__vulneranility_cvss  = $M__vulnerability_data[9];
	$V__vulnerability_description  = $M__vulnerability_data[10];
	$V__vulnerability_solution = $M__vulnerability_data[11];
	$V__vulnerability_tipo = $M__vulnerability_data[12];
	$V__vulnerability_sis = $M__vulnerability_data[13];
	
	$M__Worksheet->write($C__Actual_ROW, 5, "$V__vulnerability_IP",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 6, "$V__vulnerability_Hostname",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 7, "$V__vulnerability_protocol",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 8, "$V__vulnerability_port",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 0, "$V__vulnerability_name",$V__Format_Vulname);
	$M__Worksheet->write($C__Actual_ROW, 1, "$V__vulnerability_ID",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 2, "$V__vulnerability_cve",$V__Format_CVE);
	$M__Worksheet->write($C__Actual_ROW, 3, "$V__vulneranility_cvss",$V__Format_CVE);
	$M__Worksheet->write($C__Actual_ROW, 9, "$V__vulnerability_plataforma",$V__Format_CVE);
    
	if($V__vulnerability_riesgo=~/Alta/){
	    $M__Worksheet->write($C__Actual_ROW, 4, $V__vulnerability_riesgo,$V__Format_AltoRiesgo);
	    }
	if($V__vulnerability_riesgo=~/Media/){
	    $M__Worksheet->write($C__Actual_ROW, 4, $V__vulnerability_riesgo,$V__Format_MedioRiesgo);
	    }
	if($V__vulnerability_riesgo=~/Baja/){
	    $M__Worksheet->write($C__Actual_ROW, 4, $V__vulnerability_riesgo,$V__Format_BajoRiesgo);
	    }
	$M__Worksheet->write($C__Actual_ROW, 10, "$V__vulnerability_description",$V__Format_Vultext);
	$M__Worksheet->write($C__Actual_ROW, 11, "$V__vulnerability_solution",$V__Format_Vultext);
	$M__Worksheet->write($C__Actual_ROW, 12, "$V__vulnerability_tipo",$V__Format_General);
	$M__Worksheet->write($C__Actual_ROW, 13, "$V__vulnerability_sis",$V__Format_General);
    }
    
    $M__Worksheet->set_column(0, 0,  40.00);
    $M__Worksheet->set_column(1, 1,  13.43);
    $M__Worksheet->set_column(2, 2,  13.43);
    $M__Worksheet->set_column(3, 3,  14.86);    
    $M__Worksheet->set_column(4, 4,  13.29);
    $M__Worksheet->set_column(5, 5,  14.4);
    $M__Worksheet->set_column(6, 6,  13.86);
    $M__Worksheet->set_column(7, 7,  12.43);
    $M__Worksheet->set_column(8, 8,  10.14);
    $M__Worksheet->set_column(9, 9,  10.14);    
    $M__Worksheet->set_column(10, 10,  58.86);
    $M__Worksheet->set_column(11, 11,  58.86);
   
    return $V__vulnerability_count;
}


#### Obtiene el hostname en base a un catalogo de ombre IPs.xls dentro de la carpeta IPs.xls
###  $V__ip_addr			Direccion IP de la que se desea saber el nombre
sub S__search_hostname
{
    my ($V__ip_addr) = @_;
    my $V__hostname = "";
    my $XLS__data = Spreadsheet::ParseExcel::Simple->read('info/IPs.xls');
    foreach my $SHEET_data ($XLS__data->sheets) {
	while ($SHEET_data->has_data) {  
	    my @M__data = $SHEET_data->next_row;
	    $_ = $M__data[0];
	    if(/$V__ip_addr/==1)
	    {
	        $V__hostname = $M__data[1];
		last;
	    }
	}
    }
return "$V__hostname";
}


#### Obtiene el hostname en base a un catalogo de ombre IPs.xls dentro de la carpeta IPs.xls
###  $V__ip_addr			Direccion IP de la que se desea saber el nombre
sub S__search_sistema
{
    my ($V__ip_addr) = @_;
    my $V__hostname = "";
    my $XLS__data = Spreadsheet::ParseExcel::Simple->read('info/IPs.xls');
    foreach my $SHEET_data ($XLS__data->sheets) {
	while ($SHEET_data->has_data) {  
	    my @M__data = $SHEET_data->next_row;
	    $_ = $M__data[0];
	    if(/$V__ip_addr/==1)
	    {
	        $V__hostname = $M__data[2];
		last;
	    }
	}
    }
return "$V__hostname";
}


#### Obtiene el mes en texto (en español)
sub S__get_mes_es
{
    $_ = strftime ("%m", localtime);
    my $V__Mes_text_es="datos";
    
    if(/01/==1){$V__Mes_text_es="Enero";}
    if(/02/==1){$V__Mes_text_es="Febrero";}
    if(/03/==1){$V__Mes_text_es="Marzo";}
    if(/04/==1){$V__Mes_text_es="Abril";}
    if(/05/==1){$V__Mes_text_es="Mayo";}
    if(/06/==1){$V__Mes_text_es="Junio";}
    if(/07/==1){$V__Mes_text_es="Julio";}
    if(/08/==1){$V__Mes_text_es="Agosto";}
    if(/09/==1){$V__Mes_text_es="Septiembre";}
    if(/10/==1){$V__Mes_text_es="Octubre";}
    if(/11/==1){$V__Mes_text_es="Noviembre";}
    if(/12/==1){$V__Mes_text_es="Diciembre";}
    
    return($V__Mes_text_es);
}


#### Para cada registro, busca los elementos y genera una fila de resultado
###  $V__plugin_id  			Nombre y ruta del archivo nbe a procesar
###  $V__ip_data			IP Del dispositivo evaluado
###  $V__port_protocol			Puerto y protocolo de la vulnerabilidad
sub S__search_plugin_data
    {
	my ($V__plugin_id,$V__ip_addr,$V__port_protocol) = @_;
	my $V__plugin_data;
	my $V__plugin_data_general = "_UPS_";
	my $V__plugin_data_requested;
	my $V__plugin_plataform_requested = "general";
	my $V__aux;
	my @M__aux;
	
	my $XLS__IPs_data = Spreadsheet::ParseExcel::Simple->read('info/IPs.xls');
	my $XLS__Vul_data = Spreadsheet::ParseExcel::Simple->read('info/vulnerabilidades.xls');
	
	foreach my $SHEET_data ($XLS__IPs_data->sheets) {
	    while ($SHEET_data->has_data) {  
		my @M__data = $SHEET_data->next_row;
		$_ = $M__data[0];
		if(/$V__ip_addr/==1)
		{
		    @M__aux = split(/\n/,$M__data[4]);
		    foreach $V__aux (@M__aux)
		    {
			print "\t::\t$V__aux;\n";
		        $_ = $V__aux;
		        if(/$V__port_protocol/==1)
		        {
			    $V__plugin_plataform_requested = $M__data[4];
			    last;
			}
		    }
		    last;
		}
	    }
	}
	 
	$_ = $V__plugin_plataform_requested;
	if (/general/==0)
	{
	    @M__aux = split(/:/,$V__plugin_plataform_requested);
	    $V__plugin_plataform_requested = $M__aux[2];
	}
	 
	foreach my $SHEET_data ($XLS__Vul_data->sheets){
	    while ($SHEET_data->has_data) {  
		my @M__data = $SHEET_data->next_row;
		$_ = $M__data[1];
		if(/$V__plugin_id/==1)
		{
		    $_ = $M__data[14];
		    if (/general/==1)
		    {
			$V__plugin_data_general="$M__data[6];$M__data[1];$M__data[16];$M__data[14];$M__data[12];$M__data[13];$M__data[7];$M__data[8];$M__data[10]";
			last;
		    }
		    if (/$V__plugin_plataform_requested/==1)
		    {
			$V__plugin_data_requested = "$M__data[6];$M__data[1];$M__data[16];$M__data[14];$M__data[12];$M__data[13];$M__data[7];$M__data[8];$M__data[10]";
			last;
		    }
		    if (/$V__plugin_plataform_requested/==0 && $V__plugin_data_general=~/_UPS_/)
		    {
			$V__plugin_data_general = "$M__data[6];$M__data[1];$M__data[16];$M__data[14];$M__data[12];$M__data[13];$M__data[7];$M__data[8];$M__data[10]";
			last;
		    }
		}
	    }
	}
	
	$_ = $V__plugin_plataform_requested;
	if (/general/==0)
	{
	    $V__plugin_data = $V__plugin_data_requested;
	}
	else
	{
	    $V__plugin_data = $V__plugin_data_general;
	}
	
	return "$V__plugin_data";
        }
    
#unlink("/tmp/data.killme");