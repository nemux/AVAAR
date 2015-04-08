#!/usr/bin/perl -w
#### grouper-cmd.pl
## Vercion 0.2 


###### Modules ####

use strict;
use warnings;
use File::Slurp;        			## Leer una archivo de un solo golpe
use File::List;					## Listar directorios
use POSIX qw/strftime/; 			## Generar fechas
use Spreadsheet::WriteExcel;			## Escrivir archivos xls
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


#### Obtiene el hostname en base a un catalogo de ombre IPs.xls dentro de la carpeta IPs.xls
###  $V__ip_addr			Direccion IP de la que se desea saber el nombre
sub S__search_hostname
{
    my ($V__ip_addr) = @_;
    my $V__hostname = "Nombre desconocido";
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
   

    my $C__Actual_ROW=1;
    
    my $V__aux;
    my @M__aux;
    my $V__trash;
    my $V__counter;
   
   
    @M__IN_data = read_file($F__IN_SRC);# Lectura del Archivo completo (raw de herramienta)
   
    open(DATA,">>tmp/data.csv");
    
    
    foreach $V__row_data (@M__IN_data)
    {
	#print "\tProcesando registro $V__row_data";
	($V__reg_type,$V__reg_blank1,$V__ip_addr,$V__reg_service_port_protocol,$V__plugin_id,$V__reg_blank2,$V__plugin_rawdata) = split(/\|/,$V__row_data);
    
	$_ = $V__reg_service_port_protocol;
	s/\(//g;
	s/\)//g;
	s/\n//g;
	if (/tcp/==1 || /udp/==1 || /general/==1)
	{
	    if (/general/==1)
	    {
		print "General";
		@M__aux = split(/\//,$_);
		$V__reg_service = "general";
		$V__reg_port = "";
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
		print DATA "$V__ip_addr,$V__reg_service $V__reg_protocol/$V__reg_port\n";
	    }
	}
    }    
    close DATA;
}



=pod 

=head1 NAME 

grouper-cmd – Programa en linea de comando que genera un reporte en español en
formato xls, basado en archivos nbe de Nessus.

=head1 SYNOPSIS 

    grouper-cmd.pl [opciones] <file.nbe>  
   
=head1 DESCRIPTION 

Programa en linea de comando que genera un reporte en español en formato xls,
basado en archivos nbe de Nessus. 

=head1 OPTIONS 

Opciones

=over 4 

=item B<–v> 

Modo Vervose, muestra el proceso de conversión registro a registro a traves de
la consola.

=item B<–o=>I<value> 

Genera solo el listado de puertos habiertos. 

=back 

=head1 RETURN VALUE 
Exit values are: 

=over 4 

=item 0 

Success. 

=item 1 

Failure 

=item 8 

Bad failure. 

=back 

=head1 EXAMPLES 

An example of how to use the program to do something is: 

        grouper-cmd.pl –v –o=full in_file.nbe 

=head1 WARNINGS 

Just because you're paranoid it doesn't mean that they aren't out 
to get you. 

=head1 DIAGNOSTICS 

Most of the error messages are self explanatory. 

=head1 ENVIRONMENT 

=over 4 

=item I<ENV> 

An environment variable that affects the program. 

=back 

=head1 FILES 

=over 4 

=item /tmp/foo.lock 

A lock file used to make sure that we don't try and update 
the database from two programs at the same time. 
=back 

=head1 AUTHOR 

AntiSOL<lt>antisol@antisol.net<gt>. 

=head1 BUGS 

The command I<program> does not exist. 

=head1 SEE ALSO 

L<another_program>, L<yanp> 

=head1 COPYRIGHT 

Copyright 2009, Metnal. 

=cut
