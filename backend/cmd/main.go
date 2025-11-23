package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"reconya-ai/db"
	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/eventlog"
	"reconya-ai/internal/ipv6monitor"
	"reconya-ai/internal/network"
	"reconya-ai/internal/nicidentifier"
	"reconya-ai/internal/oui"
	"reconya-ai/internal/pingsweep"
	"reconya-ai/internal/portscan"
	"reconya-ai/internal/scan"
	"reconya-ai/internal/settings"
	"reconya-ai/internal/systemstatus"
	"reconya-ai/internal/web"
	"reconya-ai/middleware"
)

var (
	infoLogger  = log.New(os.Stdout, "", log.LstdFlags)
	errorLogger = log.New(os.Stderr, "", log.LstdFlags)
)

type App struct {
	config              *config.Config
	db                  *sql.DB
	done                chan bool
	deviceService       *device.DeviceService
	networkService      *network.NetworkService
	eventLogService     *eventlog.EventLogService
	systemStatusService *systemstatus.SystemStatusService
	settingsService     *settings.SettingsService
	scanManager         *scan.ScanManager
	nicService          *nicidentifier.NicIdentifierService
	geolocationRepo     *db.GeolocationRepository
}

func main() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGQUIT)

	infoLogger.Printf("Starting reconYa backend - PID: %d, %s/%s, Go %s",
		os.Getpid(), runtime.GOOS, runtime.GOARCH, runtime.Version())

	for {
		if err := run(); err != nil {
			errorLogger.Printf("Application error: %v", err)
			errorLogger.Println("Restarting in 2 seconds...")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
}

func run() error {
	defer func() {
		if r := recover(); r != nil {
			errorLogger.Printf("FATAL PANIC: %v\n%s", r, debug.Stack())
		}
	}()

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	app, err := initApp(cfg)
	if err != nil {
		return err
	}
	defer app.db.Close()

	app.startBackgroundWorkers()

	server := app.createServer()

	go func() {
		infoLogger.Printf("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorLogger.Printf("Server error: %v", err)
			close(app.done)
		}
	}()

	time.Sleep(500 * time.Millisecond)
	infoLogger.Printf("reconYa backend ready on port %s", cfg.Port)

	return app.waitForShutdown(server)
}

func initApp(cfg *config.Config) (*App, error) {
	sqliteDB, err := initDatabase(cfg)
	if err != nil {
		return nil, err
	}

	repoFactory := db.NewRepositoryFactory(sqliteDB, cfg.DatabaseName)
	dbManager := db.NewDBManager()

	networkRepo := repoFactory.NewNetworkRepository()
	deviceRepo := repoFactory.NewDeviceRepository()
	eventLogRepo := repoFactory.NewEventLogRepository()
	systemStatusRepo := repoFactory.NewSystemStatusRepository()
	geolocationRepo := repoFactory.NewGeolocationRepository()
	settingsRepo := repoFactory.NewSettingsRepository()

	ouiService := initOUIService(cfg)

	networkService := network.NewNetworkService(networkRepo, cfg, dbManager)
	deviceService := device.NewDeviceService(deviceRepo, networkService, cfg, dbManager, ouiService)
	eventLogService := eventlog.NewEventLogService(eventLogRepo, deviceService, dbManager)
	systemStatusService := systemstatus.NewSystemStatusService(systemStatusRepo, geolocationRepo)
	settingsService := settings.NewSettingsService(settingsRepo)
	portScanService := portscan.NewPortScanService(deviceService, eventLogService)
	pingSweepService := pingsweep.NewPingSweepService(cfg, deviceService, eventLogService, networkService, portScanService)
	ipv6MonitorService := ipv6monitor.NewIPv6MonitorService(deviceService, networkService, infoLogger)
	scanManager := scan.NewScanManager(pingSweepService, networkService, ipv6MonitorService)
	nicService := nicidentifier.NewNicIdentifierService(networkService, systemStatusService, eventLogService, deviceService, cfg)

	nicService.Identify()

	return &App{
		config:              cfg,
		db:                  sqliteDB,
		done:                make(chan bool),
		deviceService:       deviceService,
		networkService:      networkService,
		eventLogService:     eventLogService,
		systemStatusService: systemStatusService,
		settingsService:     settingsService,
		scanManager:         scanManager,
		nicService:          nicService,
		geolocationRepo:     geolocationRepo,
	}, nil
}

func initDatabase(cfg *config.Config) (*sql.DB, error) {
	sqliteDB, err := db.ConnectToSQLite(cfg.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite: %w", err)
	}

	if err := db.InitializeSchema(sqliteDB); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	if err := db.ResetPortScanCooldowns(sqliteDB); err != nil {
		infoLogger.Printf("Warning: Failed to reset port scan cooldowns: %v", err)
	}

	return sqliteDB, nil
}

func initOUIService(cfg *config.Config) *oui.OUIService {
	ouiDataPath := filepath.Join(filepath.Dir(cfg.SQLitePath), "oui")
	ouiService := oui.NewOUIService(ouiDataPath)

	if err := ouiService.Initialize(); err != nil {
		infoLogger.Printf("Warning: OUI service failed to initialize: %v", err)
		return nil
	}

	stats := ouiService.GetStatistics()
	infoLogger.Printf("OUI service: %v entries loaded", stats["total_entries"])
	return ouiService
}

func (app *App) createServer() *http.Server {
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "your-secret-key-here-replace-in-production"
	}

	webHandler := web.NewWebHandler(
		app.deviceService,
		app.eventLogService,
		app.networkService,
		app.systemStatusService,
		app.scanManager,
		app.geolocationRepo,
		app.settingsService,
		app.nicService,
		app.config,
		sessionSecret,
	)

	router := webHandler.SetupRoutes()
	loggedRouter := middleware.LoggingMiddleware(router)

	return &http.Server{
		Addr:    ":" + app.config.Port,
		Handler: loggedRouter,
	}
}

func (app *App) startBackgroundWorkers() {
	go app.runWorker("DeviceUpdater", 5*time.Second, func() error {
		return app.deviceService.UpdateDeviceStatuses()
	})

	go app.runWorker("NetworkDetection", 30*time.Second, func() error {
		app.nicService.CheckForNewNetworks()
		return nil
	})

	go app.runWorker("GeolocationCleanup", 6*time.Hour, func() error {
		return app.geolocationRepo.CleanupExpired(context.Background())
	})
}

func (app *App) runWorker(name string, interval time.Duration, task func() error) {
	defer func() {
		if r := recover(); r != nil {
			errorLogger.Printf("%s panic: %v", name, r)
		}
		infoLogger.Printf("%s stopped", name)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	infoLogger.Printf("%s started (interval: %v)", name, interval)

	for {
		select {
		case <-app.done:
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						errorLogger.Printf("%s task panic: %v", name, r)
					}
				}()
				if err := task(); err != nil {
					infoLogger.Printf("%s error: %v", name, err)
				}
			}()
		}
	}
}

func (app *App) waitForShutdown(server *http.Server) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	infoLogger.Println("Shutting down...")

	close(app.done)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	infoLogger.Println("Shutdown complete")
	return nil
}
