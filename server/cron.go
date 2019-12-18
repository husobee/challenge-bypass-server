package server

import "github.com/robfig/cron/v3"

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	cron := cron.New()
	cron.AddFunc("30 * * * *", func() {
		c.rotateIssuers()
		c.retireIssuers()
	});
}
