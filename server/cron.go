package server

import "github.com/robfig/cron/v3"

func (c *Server) SetupCronTasks() {
	c := cron.New()
	c.AddFunc("30 * * * *", func() {
		c.db.rotateIssuers()
		c.db.retireIssuers()
	});
}
