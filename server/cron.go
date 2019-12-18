package server

import "github.com/robfig/cron/v3"

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	cron := cron.New()
	cron.AddFunc("* * * * *", func() {
		if err:= c.rotateIssuers(); err != nil {
			panic(err)
		}
		if err := c.retireIssuers(); err != nil {
			panic(err)
		}
	});
	cron.Start()
}
