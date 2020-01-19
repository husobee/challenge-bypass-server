package server

import (
	"time"

	// "github.com/robfig/cron/v3"
)

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	// go jobWorker(c, RotateIssuers(c), 30 * time.Second)
	// cron := cron.New()
	// if _, err := cron.AddFunc("30 * * * *", func() {
	// 	if err:= RotateIssuers(); err != nil {
	// 		panic(err)
	// 	}
	// 	if err := c.retireIssuers(); err != nil {
	// 		panic(err)
	// 	}
	// }); err != nil {
	// 	panic(err)
	// }
	// cron.Start()
}

func jobWorker(context *Server, job func(*Server) (bool, error), duration time.Duration) {
	ticker := time.NewTicker(duration)
	for {
		attempted, err := job(context)
		if err != nil {
			panic(err)
		}
		if !attempted || err != nil {
			<-ticker.C
		}
	}
}