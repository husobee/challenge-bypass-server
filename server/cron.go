package server

import "github.com/robfig/cron/v3"

func (c *Server) SetupCronTasks() {
	cron := cron.New()
	cron.AddFunc("30 * * * *", func() {
		c.rotateIssuers()
		c.retireIssuers()
	});
}
