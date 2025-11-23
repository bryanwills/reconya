package nicidentifier

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/eventlog"
	"reconya-ai/internal/network"
	"reconya-ai/internal/systemstatus"
	"reconya-ai/models"
)

var (
	dockerRanges = []string{
		"172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16", "172.20.0.0/16",
		"172.21.0.0/16", "172.22.0.0/16", "172.23.0.0/16", "172.24.0.0/16",
		"172.25.0.0/16", "172.26.0.0/16", "172.27.0.0/16", "172.28.0.0/16",
		"172.29.0.0/16", "172.30.0.0/16", "172.31.0.0/16",
	}

	privateRanges = []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
	}

	httpClient = &http.Client{Timeout: 10 * time.Second}
)

type NicIdentifierService struct {
	networkService      *network.NetworkService
	systemStatusService *systemstatus.SystemStatusService
	eventLogService     *eventlog.EventLogService
	deviceService       *device.DeviceService
	config              *config.Config
	logger              *log.Logger
}

type DetectedNetwork struct {
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}

type interfaceInfo struct {
	name string
	ip   net.IP
	cidr string
}

func NewNicIdentifierService(
	networkService *network.NetworkService,
	systemStatusService *systemstatus.SystemStatusService,
	eventLogService *eventlog.EventLogService,
	deviceService *device.DeviceService,
	cfg *config.Config,
) *NicIdentifierService {
	return &NicIdentifierService{
		networkService:      networkService,
		systemStatusService: systemStatusService,
		eventLogService:     eventLogService,
		deviceService:       deviceService,
		config:              cfg,
		logger:              log.Default(),
	}
}

func (s *NicIdentifierService) Identify() {
	s.logger.Println("Starting network identification")

	nic := s.getLocalNic()
	if nic.IPv4 == "" {
		s.logger.Println("No local NIC found")
		return
	}
	s.logger.Printf("Local NIC: %s (%s)", nic.Name, nic.IPv4)

	s.CheckForNewNetworks()

	networkEntity := s.findNetworkForIP(nic.IPv4)

	localDevice, err := s.createLocalDevice(nic)
	if err != nil {
		s.logger.Printf("Failed to create local device: %v", err)
		return
	}

	if err := s.updateSystemStatus(localDevice, networkEntity); err != nil {
		s.logger.Printf("Failed to update system status: %v", err)
		return
	}

	s.logDiscoveryEvents(localDevice.ID)
}

func (s *NicIdentifierService) findNetworkForIP(ipStr string) *models.Network {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	cidr := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	existing, err := s.networkService.FindByCIDR(cidr)
	if err != nil {
		s.logger.Printf("Error searching for network %s: %v", cidr, err)
		return nil
	}

	if existing != nil {
		s.logger.Printf("Found existing network: %s", existing.CIDR)
	}
	return existing
}

func (s *NicIdentifierService) createLocalDevice(nic models.NIC) (*models.Device, error) {
	localDevice := &models.Device{
		Name:   nic.Name,
		IPv4:   nic.IPv4,
		Status: models.DeviceStatusOnline,
	}
	return s.deviceService.CreateOrUpdate(localDevice)
}

func (s *NicIdentifierService) updateSystemStatus(device *models.Device, networkEntity *models.Network) error {
	publicIP, err := s.getPublicIP()
	if err != nil {
		s.logger.Printf("Failed to get public IP: %v", err)
		publicIP = ""
	} else {
		s.logger.Printf("Public IP: %s", publicIP)
	}

	status := models.SystemStatus{
		LocalDevice: *device,
		PublicIP:    &publicIP,
	}

	if networkEntity != nil {
		status.NetworkID = networkEntity.ID
	}

	if publicIP != "" {
		if geo, err := s.systemStatusService.FetchGeolocation(publicIP); err == nil && geo != nil {
			status.Geolocation = geo
			s.logger.Printf("Geolocation: %s, %s", geo.City, geo.Country)
		}
	}

	_, err = s.systemStatusService.CreateOrUpdate(&status)
	return err
}

func (s *NicIdentifierService) logDiscoveryEvents(deviceID string) {
	s.eventLogService.CreateOne(&models.EventLog{
		Type:     models.LocalIPFound,
		DeviceID: &deviceID,
	})
	s.eventLogService.CreateOne(&models.EventLog{
		Type: models.LocalNetworkFound,
	})
}

func (s *NicIdentifierService) getLocalNic() models.NIC {
	interfaces := s.getActiveInterfaces()

	var candidates, dockerNics []models.NIC
	for _, iface := range interfaces {
		nic := models.NIC{Name: iface.name, IPv4: iface.ip.String()}
		if s.isDockerNetwork(iface.ip) {
			dockerNics = append(dockerNics, nic)
		} else {
			candidates = append(candidates, nic)
		}
	}

	for _, nic := range candidates {
		if s.isPrivateNetwork(net.ParseIP(nic.IPv4)) {
			return nic
		}
	}

	if len(candidates) > 0 {
		return candidates[0]
	}

	if len(dockerNics) > 0 {
		return dockerNics[0]
	}

	return models.NIC{}
}

func (s *NicIdentifierService) getActiveInterfaces() []interfaceInfo {
	var result []interfaceInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		s.logger.Printf("Error getting interfaces: %v", err)
		return result
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}

			result = append(result, interfaceInfo{
				name: iface.Name,
				ip:   ip,
				cidr: ipNet.String(),
			})
		}
	}

	return result
}

func (s *NicIdentifierService) isDockerNetwork(ip net.IP) bool {
	return s.ipInRanges(ip, dockerRanges)
}

func (s *NicIdentifierService) isPrivateNetwork(ip net.IP) bool {
	return s.ipInRanges(ip, privateRanges)
}

func (s *NicIdentifierService) ipInRanges(ip net.IP, ranges []string) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *NicIdentifierService) getPublicIP() (string, error) {
	resp, err := httpClient.Get("https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("failed to fetch public IP: %w", err)
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	return string(ip), nil
}

func (s *NicIdentifierService) CheckForNewNetworks() {
	interfaces := s.getActiveInterfaces()

	for _, iface := range interfaces {
		if s.isDockerNetwork(iface.ip) {
			continue
		}

		ipNet, err := parseNetworkCIDR(iface.cidr)
		if err != nil {
			continue
		}

		s.suggestNetworkIfNew(ipNet, iface.name)
	}
}

func (s *NicIdentifierService) suggestNetworkIfNew(ipNet *net.IPNet, ifaceName string) {
	networkIP := ipNet.IP.Mask(ipNet.Mask)
	ones, _ := ipNet.Mask.Size()
	baseCIDR := fmt.Sprintf("%s/%d", networkIP.String(), ones)

	existing, err := s.networkService.FindByCIDR(baseCIDR)
	if err != nil || existing != nil {
		return
	}

	s.logger.Printf("New network detected: %s on %s", baseCIDR, ifaceName)
	s.eventLogService.CreateOne(&models.EventLog{
		Type:        models.NewNetworkDetected,
		Description: fmt.Sprintf("New network %s detected on %s", baseCIDR, ifaceName),
	})
}

func (s *NicIdentifierService) GetDetectedNetworks() []DetectedNetwork {
	var detected []DetectedNetwork

	interfaces := s.getActiveInterfaces()
	for _, iface := range interfaces {
		if s.isDockerNetwork(iface.ip) {
			continue
		}

		ipNet, err := parseNetworkCIDR(iface.cidr)
		if err != nil {
			continue
		}

		networkIP := ipNet.IP.Mask(ipNet.Mask)
		ones, _ := ipNet.Mask.Size()
		baseCIDR := fmt.Sprintf("%s/%d", networkIP.String(), ones)

		existing, err := s.networkService.FindByCIDR(baseCIDR)
		if err != nil || existing != nil {
			continue
		}

		detected = append(detected, DetectedNetwork{
			CIDR:      baseCIDR,
			Interface: iface.name,
			IP:        iface.ip.String(),
		})
	}

	return detected
}

func parseNetworkCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	return ipNet, err
}
