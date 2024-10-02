package main

import (
	//"bufio"
	//"strings"

	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/configs"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/logger"
	//"github.com/Gaviola/Proyecto_CEI_Back.git/internal/repositories"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/routes"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/services"
	//"github.com/Gaviola/Proyecto_CEI_Back.git/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"

	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/spf13/viper"
)

func main() {

	// Configurar CORS usando la librería rs/cors
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"},                   // Orígenes permitidos
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, // Métodos permitidos
		AllowedHeaders:   []string{"Content-Type", "Authorization"},           // Cabeceras permitidas
		AllowCredentials: true,
	})

	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Timeout(60 * time.Second))

	// Rutas de la aplicacion
	routes.LoginRoutes(r)
	routes.RegisterRoutes(r)
	routes.AdminRoutes(r)

	handler := c.Handler(r)

	// Initialize Viper across the application
	configs.InitializeViper()
	fmt.Println("Viper initialized...")

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()
	fmt.Println("Zap Custom Logger initialized...")

	// Initialize Oauth2 Services
	services.InitializeOAuthGoogle()
	fmt.Println("OAuth2 Services initialized...")

	fmt.Println("Servidor escuchando en http://localhost:8080")
	// logger.Log.Info("Started running on http://localhost:" + viper.GetString("port")) // Log the port where the server is running
	log.Fatal(http.ListenAndServe(":8080", handler))

	

	var opcion int
	fmt.Println("DEBUG MENU")
	fmt.Println("[1] \tSetear variables de entorno")
	fmt.Println("[2] \tGoogle Login")
	fmt.Println("[3] \tPrueba de ItemTypes")
	fmt.Println("[4] \tPrueba de Items")
	fmt.Println("[5] \tPrueba de Crear ItemType")
	fmt.Println("[OTRO] \tSalir")

	fmt.Print("> Ingrese una opción: ")
	fmt.Scan(&opcion)
	fmt.Println()

	switch opcion {
	case 1:
		fmt.Println("Has seleccionado la opción 1")
		//Crear llave secreta
		key := make([]byte, 64)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatal(err)
		}
		secret := base64.StdEncoding.EncodeToString(key)
		err = os.Setenv("JWT_SECRET", secret)
		if err != nil {
			http.Error(nil, "Error al setear la variables de entorno", http.StatusInternalServerError)
			return
		}

		fmt.Println("Servidor escuchando en http://localhost:8080")
		logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
		log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), handler))

	case 2:
		w := http.ResponseWriter(nil)
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			log.Fatal(err)
		}

		routes.LoginGoogle(w, r)

		log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
	default:
		fmt.Println("Saliendo...")
	}

}
