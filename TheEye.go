package main


import "github.com/fatih/color"
import "strings"
import "os/exec"
import "time"
import "os"


var Version string = "1.0.4"


type ARPCahce struct {
	ip [255]string
	mac [255]string
	TableSize int
}


var CheckARPTableDuration time.Duration = 5
var CheckHostsDuration time.Duration = 15
var CheckConnectionsDuration time.Duration = 5
var Verbose bool = false
var ARP ARPCahce



func main() {

	ARGS := os.Args[1:]
	color.Green("Version : "+Version)

	if len(ARGS) != 0 {
		if ARGS[0] == "--check-arp" {
			CheckARPTable(0)
			os.Exit(0)
		}
		if ARGS[0] == "--check-host" {
			CheckHosts(0)
			os.Exit(0)
		}
		if ARGS[0] == "--check-connections" {
			CheckConnections(0)
			os.Exit(0)
		}
	}


	go CheckHosts(CheckARPTableDuration)
	go CheckARPTable(CheckARPTableDuration)
	CheckConnections(CheckConnectionsDuration)
}


func CheckARPTable(Duration time.Duration) {

  	Red := color.New(color.FgRed)
  	BoldRed := Red.Add(color.Bold)
  	Yellow := color.New(color.FgYellow)
  	BoldYellow := Yellow.Add(color.Bold)
  	Green := color.New(color.FgGreen)
  	BoldGreen := Green.Add(color.Bold)

  	BoldGreen.Println("[*] ARP cache surveillance started")
  	if Duration == 0 {
  		Duration = 3
		exec.Command("sh", "-c", "arp -d -a'").Run()// Clear arp table
		time.Sleep(Duration*time.Second)
		ARP_Table,_ := exec.Command("sh", "-c", "arp -a").Output()
		TableEntries := strings.Split(string(ARP_Table), "\n")
		ARP.TableSize = (len(TableEntries)-1)
		for i:=0; i < ARP.TableSize; i++ {
			Temp := strings.Split(TableEntries[i], "at")
			ARP.ip[i] = Temp[0]
			ARP.mac[i] = Temp[1]
		}

		if Verbose == true {
			for i:=0; i < ARP.TableSize; i++ {
				BoldYellow.Println("ARP Cache : "+ARP.ip[i]+" --> "+ARP.mac[i])	
			}	
		}

		for j:=0; j < ARP.TableSize; j++ {
			for k:=(j+1); k < ARP.TableSize; k++ {
				if ARP.mac[j] == ARP.mac[k] {
					BoldRed.Println("[!] ARP poisoning detected !")
					BoldRed.Print("[!] Malicious ip : ")
					BoldRed.Println(ARP.ip[k])
					exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'ARP poisoning detected !'").Run()
					exec.Command("sh", "-c", string("notify-send -u critical 'The Eye' 'Malicious ip "+ARP.ip[k]+"'")).Run()
					exec.Command("sh", "-c", "espeak 'Warning, arp poisoning detected'").Run()

				}
			}
		}
  	}else {
		for ;; {
			exec.Command("sh", "-c", "arp -d -a'").Run()// Clear arp table
			time.Sleep(Duration*time.Second)
			ARP_Table,_ := exec.Command("sh", "-c", "arp -a").Output()
			TableEntries := strings.Split(string(ARP_Table), "\n")
			ARP.TableSize = (len(TableEntries)-1)
			for i:=0; i < ARP.TableSize; i++ {
				Temp := strings.Split(TableEntries[i], "at")
				ARP.ip[i] = Temp[0]
				ARP.mac[i] = Temp[1]
			}

			if Verbose == true {
				for i:=0; i < ARP.TableSize; i++ {
					BoldYellow.Println("ARP Cache : "+ARP.ip[i]+" --> "+ARP.mac[i])	
				}	
			}

			for j:=0; j < ARP.TableSize; j++ {
				for k:=(j+1); k < ARP.TableSize; k++ {
					if ARP.mac[j] == ARP.mac[k] && !strings.Contains(ARP.mac[j], "<incomplete>") && !strings.Contains(ARP.mac[k], "<incomplete>") {
						BoldRed.Println("[!] ARP poisoning detected !")
						BoldRed.Print("[!] Malicious ip : ")
						BoldRed.Println(ARP.ip[k])
						exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'ARP poisoning detected !'").Run()
						exec.Command("sh", "-c", string("notify-send -u critical 'The Eye' 'Malicious ip "+ARP.ip[k]+"'")).Run()
						exec.Command("sh", "-c", "espeak 'Warning, arp poisoning detected'").Run()

					}
				}
			}
		}
  	}
}


func CheckHosts(Duration time.Duration) {

	Red := color.New(color.FgRed)
  	BoldRed := Red.Add(color.Bold)
  	Green := color.New(color.FgGreen)
  	BoldGreen := Green.Add(color.Bold)

  	BoldGreen.Println("[*] Host file surveillance started")

  	if Duration == 0 {
  		// Add suspicous address recognition
  	}else {
		for ;; {
			DefaultHostsFile, _ := exec.Command("sh", "-c", "cat /etc/hosts").Output()
			time.Sleep(Duration*time.Second)
			HostsFile,_ := exec.Command("sh", "-c", "cat /etc/hosts").Output()

			if string(HostsFile) != string(DefaultHostsFile) {
				BoldRed.Println("[!] Host file has been corrupted !")
				exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'Host file has been corrupted !'").Run()
				exec.Command("sh", "-c", "espeak 'Warning, host file has been corrupted'").Run()
			}else{
				if Verbose == true {
					BoldGreen.Println("[+] Host file Clean")
				}
			}
		}
  	}

}

func CheckConnections(Duration time.Duration) {

  	Red := color.New(color.FgRed)
  	BoldRed := Red.Add(color.Bold)
  	Green := color.New(color.FgGreen)
  	BoldGreen := Green.Add(color.Bold)

  	BoldGreen.Println("[*] Suspicous connection surveillance started")

  	if Duration == 0 {
		AllConnections, _ := exec.Command("sh", "-c", "netstat -t | grep ESTABLISHED").Output()
		Connections := strings.Split(string(AllConnections), "\n")
		for i := 0; i < len(Connections); i++ {
			if !strings.Contains(Connections[i], ":http") && !strings.Contains(Connections[i], ":https") && !strings.Contains(Connections[i], ":netbios-ssn") {
				if strings.Contains(Connections[i], ":") {
					Foreign := strings.Split(Connections[i], ":")
					if !strings.Contains(Foreign[1], "localhost") {
						DotCount := strings.Split(Foreign[1], ".")
						if len(DotCount) == 4 {
							BoldRed.Print("[!] Suspicous connection detected ! ----> ")
							BoldRed.Println(Foreign[1])
							exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'Suspicous connection detected !'").Run()
							exec.Command("sh", "-c", "espeak 'Warning, suspicous connection detected'").Run()
						}
					}
				}
			}
		}
  	}else {
  		for ;; {
			AllConnections, _ := exec.Command("sh", "-c", "netstat -t | grep ESTABLISHED").Output()
			Connections := strings.Split(string(AllConnections), "\n")
			for i := 0; i < len(Connections); i++ {
				if !strings.Contains(Connections[i], ":http") && !strings.Contains(Connections[i], ":https") && !strings.Contains(Connections[i], ":netbios-ssn") {
					if strings.Contains(Connections[i], ":") {
						Foreign := strings.Split(Connections[i], ":")
						if !strings.Contains(Foreign[1], "localhost") {
							DotCount := strings.Split(Foreign[1], ".")
							if len(DotCount) == 4 {
								BoldRed.Print("[!] Suspicous connection detected ! ----> ")
								BoldRed.Println(Foreign[1])
								SuspConn,_ := exec.Command("sh", "-c", string("netstat -p | grep '"+Foreign[1]+"'")).Output()
								PID := strings.Split(string(SuspConn), "ESTABLISHED")
								if len(PID) < 2 {
									exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'Suspicous connection detected !	\nPID: ?'").Run()
								}else{
									exec.Command("sh", "-c", "notify-send -u critical 'The Eye' 'Suspicous connection detected !	\n"+PID[1]+"'").Run()
								}
								
								exec.Command("sh", "-c", "espeak 'Warning, suspicous connection detected'").Run()
							}
						}
					}
				}
			}
			time.Sleep(Duration*time.Second)
		}
  	}
}