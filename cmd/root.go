/*
Copyright © 2024 Antonio S. Dromundo sebastiandromundo(at)outlook.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"github.com/asdromundo/sec_report/pkg/pentesting"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	pingFlag       bool
	nslookupFlag   bool
	tracerouteFlag bool
	whoisFlag      bool
	sublist3rFlag  bool
	subfinderFlag  bool
	findomainFlag  bool
	dnsmapFlag     bool
	dnsreconFlag   bool
	nmapFlag       bool
	etherapeFlag   bool
	printFlag      bool
	outputFlag     string
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sec_report [domain or IP]",
	Short: "Generate a security report for a given domain or IP",
	Long: `sec_report es una herramienta de línea de comandos diseñada para generar un informe de seguridad exhaustivo para un dominio o una dirección IP específica. Esta aplicación utiliza una variedad de herramientas de red y DNS para recopilar información valiosa y proporcionar una visión completa de la postura de seguridad de un sistema.

Las siguientes aplicaciones se utilizan para recopilar datos relevantes durante el proceso de generación de informes:

ping: Realiza pruebas de conectividad básicas y mide el tiempo de respuesta entre el sistema local y el destino especificado.
nslookup: Proporciona información de resolución de nombres, como direcciones IP y registros de DNS asociados con un nombre de dominio.
traceroute: Muestra la ruta que los paquetes de red toman desde el sistema local hasta el destino especificado, identificando los saltos intermedios.
whois: Permite obtener información sobre el propietario y otros detalles de un nombre de dominio o una dirección IP.
sublist3r: Utiliza la técnica de enumeración de subdominios para descubrir subdominios asociados con el dominio especificado.
subfinder: Similar a sublist3r, subfinder también se utiliza para enumerar subdominios y descubrir posibles puntos de entrada adicionales.
findomain: Otra herramienta de enumeración de subdominios que ayuda a descubrir subdominios adicionales asociados con el dominio especificado.
dnsmap: Realiza un análisis de mapeo de DNS, identificando las direcciones IP asociadas con nombres de dominio específicos.
dnsrecon: Proporciona funcionalidades avanzadas para la enumeración de subdominios y la recopilación de información de DNS.
nmap: Una herramienta de escaneo de puertos y detección de servicios que identifica los servicios disponibles en los sistemas de destino.
etherApe: Proporciona una representación visual de la actividad de red, ayudando a identificar patrones y anomalías.

sec_report integra estas herramientas de forma eficiente para recopilar y analizar datos de manera automatizada, proporcionando a los usuarios un informe detallado sobre la seguridad y la infraestructura de red asociada con el dominio o la dirección IP proporcionados.
	`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// Check if there are any arguments passed
		if len(args) < 1 || !pentesting.IsValidURL(args[0]) {
			fmt.Println("Error: Please provide a valid domain or IP address.")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}

		url := args[0]
		fmt.Printf("Generating security report for: %s\n", url)
		generateReport(url)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sec_report.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.PersistentFlags().BoolVar(&pingFlag, "ping", false, "Perform a ping test")
	rootCmd.PersistentFlags().BoolVar(&nslookupFlag, "nslookup", false, "Perform a DNS lookup")
	rootCmd.PersistentFlags().BoolVar(&tracerouteFlag, "traceroute", false, "Perform a traceroute")
	rootCmd.PersistentFlags().BoolVar(&whoisFlag, "whois", false, "Perform a WHOIS lookup")
	rootCmd.PersistentFlags().BoolVar(&sublist3rFlag, "sublist3r", false, "Perform a sublist3r lookup")
	rootCmd.PersistentFlags().BoolVar(&subfinderFlag, "subfinder", false, "Perform a subfinder lookup")
	rootCmd.PersistentFlags().BoolVar(&findomainFlag, "findomain", false, "Perform a findomain lookup")
	rootCmd.PersistentFlags().BoolVar(&dnsmapFlag, "dnsmap", false, "Perform a dnsmap lookup")
	rootCmd.PersistentFlags().BoolVar(&dnsreconFlag, "dnsrecon", false, "Perform a dnsrecon lookup")
	rootCmd.PersistentFlags().BoolVar(&nmapFlag, "nmap", false, "Perform an Nmap scan")
	rootCmd.PersistentFlags().BoolVar(&etherapeFlag, "etherape", false, "Open EtherApe for network visualization")
	rootCmd.PersistentFlags().BoolVar(&printFlag, "print", false, "Print results in command line")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "", "Output HTML report file")

	viper.BindPFlag("ping", rootCmd.PersistentFlags().Lookup("ping"))
	viper.BindPFlag("nslookup", rootCmd.PersistentFlags().Lookup("nslookup"))
	viper.BindPFlag("traceroute", rootCmd.PersistentFlags().Lookup("traceroute"))
	viper.BindPFlag("whois", rootCmd.PersistentFlags().Lookup("whois"))
	viper.BindPFlag("sublist3r", rootCmd.PersistentFlags().Lookup("sublist3r"))
	viper.BindPFlag("subfinder", rootCmd.PersistentFlags().Lookup("subfinder"))
	viper.BindPFlag("findomain", rootCmd.PersistentFlags().Lookup("findomain"))
	viper.BindPFlag("dnsmap", rootCmd.PersistentFlags().Lookup("dnsmap"))
	viper.BindPFlag("dnsrecon", rootCmd.PersistentFlags().Lookup("dnsrecon"))
	viper.BindPFlag("nmap", rootCmd.PersistentFlags().Lookup("nmap"))
	viper.BindPFlag("etherape", rootCmd.PersistentFlags().Lookup("etherape"))
	viper.BindPFlag("print", rootCmd.PersistentFlags().Lookup("print"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".sec_report" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".sec_report")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func generateReport(url string) {

	// var results bytes.Buffer
	var wg sync.WaitGroup

	// Crear un slice de buffers para los resultados parciales
	var partial_results []*bytes.Buffer

	// Perform tasks based on flags
	if pingFlag {
		fmt.Println("Performing ping...")
	}
	if tracerouteFlag {
		pentesting.RunProgramRoutine(pentesting.Traceroute, url, &partial_results, &wg)
	}
	if nslookupFlag {
		pentesting.RunProgramRoutine(pentesting.Nslookup, url, &partial_results, &wg)
	}
	if whoisFlag {
		pentesting.RunProgramRoutine(pentesting.Whois, url, &partial_results, &wg)
	}
	if nmapFlag {
		pentesting.RunProgramRoutine(pentesting.Nmap, url, &partial_results, &wg)
	}
	if dnsmapFlag {
		pentesting.RunProgramRoutine(pentesting.Dnsmap, url, &partial_results, &wg)
	}

	// Build report from partial results
	wg.Wait()
	var results bytes.Buffer
	for _, result := range partial_results {
		results.Write(result.Bytes())
	}

	if outputFlag == "" {
		fmt.Println(results.String())
	} else {
		// Save results to file
		if err := pentesting.SaveResultsToFile(results, outputFlag); err != nil {
			fmt.Printf("Error al guardar los resultados en el archivo: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Resultados guardados en: %s\n", outputFlag)
	}
}
